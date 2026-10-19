//go:build windows

package cim

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/backuptar"
	"github.com/Microsoft/hcsshim/internal/wclayer"
	"github.com/Microsoft/hcsshim/pkg/ociwclayer"
	"golang.org/x/sys/windows"
)

const (
	scratchTombstonesFile = `Windows\container_tombstones.json`
	scratchHivesDir       = `WcSandboxState\Hives`
	scratchSystemVolInfo  = `System Volume Information`
	scratchSandboxState   = `WcSandboxState`
)

// fixedFiletime is the time stamp of the synthetic "Files" and "Hives" directory entries (2000-01-01), so
// that exporting the same scratch twice gives the same tar.
var fixedFiletime = windows.Filetime{LowDateTime: 0xD53E8000, HighDateTime: 0x01BF53EB}

// ExportScratchToTar writes the changes a process-isolated container made in a CIM-based scratch layer as an
// OCI layer tar stream, in the format ImportCimLayerFromTar reads: file changes under "Files/", deletions as
// whiteouts, and the registry hive deltas under "Hives/".
//
// `scratchPath` is the scratch layer directory (containing sandbox.vhdx). The container must have stopped and
// released the scratch. The caller must hold backup, restore and security privileges.
func ExportScratchToTar(ctx context.Context, w io.Writer, scratchPath string) (retErr error) {
	if err := wclayer.ActivateLayer(ctx, scratchPath); err != nil {
		return fmt.Errorf("activate scratch layer: %w", err)
	}
	defer func() {
		if err := wclayer.DeactivateLayer(ctx, scratchPath); err != nil && retErr == nil {
			retErr = fmt.Errorf("deactivate scratch layer: %w", err)
		}
	}()
	vol, err := wclayer.GetLayerMountPath(ctx, scratchPath)
	if err != nil {
		return fmt.Errorf("get scratch mount path: %w", err)
	}
	root := strings.TrimSuffix(vol, `\`) + `\`

	tombstones, err := readScratchTombstones(root)
	if err != nil {
		return err
	}

	t := tar.NewWriter(w)
	if err := writeSyntheticDir(t, "Files"); err != nil {
		return err
	}
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel := strings.TrimPrefix(p, root)
		switch {
		case strings.EqualFold(rel, scratchSystemVolInfo), strings.EqualFold(rel, scratchSandboxState):
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		case strings.EqualFold(rel, scratchTombstonesFile):
			return nil
		}
		return writeScratchEntry(t, p, "Files/"+filepath.ToSlash(rel))
	})
	if walkErr != nil {
		return walkErr
	}
	for _, ts := range tombstones {
		ts = filepath.ToSlash(ts)
		dir, base := "", ts
		if i := strings.LastIndex(ts, "/"); i >= 0 {
			dir, base = ts[:i+1], ts[i+1:]
		}
		if err := t.WriteHeader(&tar.Header{Name: "Files/" + dir + ociwclayer.WhiteoutPrefix + base}); err != nil {
			return err
		}
	}

	if err := writeSyntheticDir(t, "Hives"); err != nil {
		return err
	}
	hives, err := os.ReadDir(filepath.Join(root, scratchHivesDir))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, h := range hives {
		// skip the registry transaction logs, only the deltas belong in the layer
		if h.IsDir() || !strings.HasSuffix(strings.ToLower(h.Name()), "_delta") {
			continue
		}
		if err := writeScratchEntry(t, filepath.Join(root, scratchHivesDir, h.Name()), "Hives/"+h.Name()); err != nil {
			return err
		}
	}
	return t.Close()
}

// readScratchTombstones returns the layer-relative paths of the files the container deleted.
func readScratchTombstones(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, scratchTombstonesFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read tombstones: %w", err)
	}
	var doc struct {
		TombstonePaths [][]json.RawMessage `json:"tombstonePaths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse tombstones: %w", err)
	}
	var out []string
	for _, e := range doc.TombstonePaths {
		if len(e) == 0 {
			continue
		}
		var path string
		if err := json.Unmarshal(e[0], &path); err != nil {
			return nil, fmt.Errorf("parse tombstone path: %w", err)
		}
		out = append(out, path)
	}
	return out, nil
}

func writeSyntheticDir(t *tar.Writer, name string) error {
	fi := &winio.FileBasicInfo{
		CreationTime:   fixedFiletime,
		LastAccessTime: fixedFiletime,
		LastWriteTime:  fixedFiletime,
		ChangeTime:     fixedFiletime,
		FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY,
	}
	hdr := backuptar.BasicInfoHeader(name, 0, fi)
	return t.WriteHeader(hdr)
}

// writeScratchEntry adds one file or directory from the activated scratch volume to the tar.
func writeScratchEntry(t *tar.Writer, osPath, name string) error {
	f, err := winio.OpenForBackup(osPath, syscall.GENERIC_READ|winio.ACCESS_SYSTEM_SECURITY, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING)
	if err != nil {
		return fmt.Errorf("open %s: %w", osPath, err)
	}
	defer f.Close()
	fi, err := winio.GetFileBasicInfo(f)
	if err != nil {
		return fmt.Errorf("get file info %s: %w", osPath, err)
	}
	// Reading a file updates its access time, which would make the tar differ between exports.
	fi.LastAccessTime = fi.LastWriteTime
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", osPath, err)
	}
	size := int64(0)
	if !st.IsDir() {
		size = st.Size()
	}
	r := winio.NewBackupFileReader(f, true)
	defer r.Close()
	return backuptar.WriteTarFileFromBackupStream(t, r, name, size, fi)
}
