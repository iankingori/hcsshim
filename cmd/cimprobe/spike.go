//go:build windows

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/Microsoft/hcsshim/internal/security"
	"github.com/Microsoft/hcsshim/internal/wclayer"
	"github.com/Microsoft/hcsshim/internal/wclayer/cim"
	"github.com/Microsoft/hcsshim/pkg/ociwclayer"
	ociwcim "github.com/Microsoft/hcsshim/pkg/ociwclayer/cim"
	"golang.org/x/sys/windows"
)

// spike: cimprobe import <tar|tgz> <layerDir> <cimPath> [<parentLayerDir> <parentCimPath>]
//
//	cimprobe mount <cimPath>
func spike(args []string) error {
	ctx := context.Background()
	switch args[0] {
	case "scan": // gunzip + walk the tar, no writing: the floor for any import
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
		if err != nil {
			return err
		}
		start, c0 := time.Now(), cpuTimes()
		t := tar.NewReader(gz)
		var n, bytes int64
		for {
			h, err := t.Next()
			if err != nil {
				break
			}
			b, _ := io.Copy(io.Discard, t)
			n++
			bytes += b + h.Size*0
		}
		fmt.Printf("scan: %s %d entries %d bytes  %s\n", time.Since(start).Round(time.Millisecond), n, bytes, cpuSince(c0))
		return nil
	case "scratch": // create an empty NTFS-formatted scratch VHDX the way the containerd cimfs snapshotter does
		dir := args[1]
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		p := filepath.Join(dir, "sandbox.vhdx")
		start := time.Now()
		h, err := vhd.CreateVirtualDisk(p, vhd.VirtualDiskAccessNone, vhd.CreateVirtualDiskFlagNone, &vhd.CreateVirtualDiskParameters{
			Version:  2,
			Version2: vhd.CreateVersion2{MaximumSize: 10 << 30, BlockSizeInBytes: 1 << 20},
		})
		if err != nil {
			return fmt.Errorf("create vhd: %w", err)
		}
		err = computestorage.FormatWritableLayerVhd(ctx, windows.Handle(h))
		syscall.CloseHandle(h)
		if err != nil {
			return fmt.Errorf("format vhd: %w", err)
		}
		if err := security.GrantVmGroupAccess(p); err != nil {
			return fmt.Errorf("grant vm group access: %w", err)
		}
		fmt.Printf("scratch: %s %s\n", time.Since(start).Round(time.Millisecond), p)
		return nil
	case "rawscratch": // activate a CIM scratch layer without the union filter and list what the container left in it
		dir := args[1]
		if err := wclayer.ActivateLayer(ctx, dir); err != nil {
			return fmt.Errorf("activate: %w", err)
		}
		defer wclayer.DeactivateLayer(ctx, dir)
		mp, err := wclayer.GetLayerMountPath(ctx, dir)
		if err != nil {
			return err
		}
		fmt.Printf("scratch volume: %s\n", mp)
		n := 0
		filepath.WalkDir(mp, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				fmt.Printf("  walk error %s: %v\n", p, err)
				return nil
			}
			if p == mp {
				return nil
			}
			n++
			if n <= 40 {
				info, _ := d.Info()
				var attrs uint32
				if info != nil {
					if sys, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
						attrs = sys.FileAttributes
					}
				}
				size := int64(0)
				if info != nil {
					size = info.Size()
				}
				fmt.Printf("  %s size=%d attrs=%#x\n", strings.TrimPrefix(p, mp), size, attrs)
			}
			return nil
		})
		fmt.Printf("total entries: %d\n", n)
		return nil
	case "importwc": // the current path: HCS ImportLayer into a standard layer dir
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
		if err != nil {
			return err
		}
		if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}); err != nil {
			return err
		}
		start, c0 := time.Now(), cpuTimes()
		var n int64
		err = winio.RunWithPrivileges([]string{winio.SeSecurityPrivilege}, func() error {
			var e error
			n, e = ociwclayer.ImportLayerFromTar(ctx, gz, args[2], nil)
			return e
		})
		fmt.Printf("importwc: %s (%d bytes of files) err=%v  %s\n", time.Since(start).Round(time.Millisecond), n, err, cpuSince(c0))
		return err
	case "import":
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		br := bufio.NewReaderSize(f, 1<<20)
		var r io.Reader = br
		if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
			gz, err := gzip.NewReader(br)
			if err != nil {
				return err
			}
			defer gz.Close()
			r = gz
		}
		var pLayers, pCims []string
		if len(args) >= 6 {
			pLayers, pCims = []string{args[4]}, []string{args[5]}
		}
		if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}); err != nil {
			return err
		}
		start, c0 := time.Now(), cpuTimes()
		var n int64
		err = winio.RunWithPrivileges([]string{winio.SeSecurityPrivilege}, func() error {
			var e error
			n, e = ociwcim.ImportCimLayerFromTar(ctx, r, args[2], args[3], pLayers, pCims)
			return e
		})
		fmt.Printf("import: %s (%d bytes of files) err=%v  %s\n", time.Since(start).Round(time.Millisecond), n, err, cpuSince(c0))
		return err
	case "mount":
		start := time.Now()
		vol, err := cim.MountForkedCimLayer(ctx, args[1], "cimspike")
		if err != nil {
			return err
		}
		fmt.Printf("mount: %s -> %s\n", time.Since(start).Round(time.Millisecond), vol)
		defer func() {
			s := time.Now()
			err := cim.UnmountCimLayer(ctx, vol)
			fmt.Printf("unmount: %s err=%v\n", time.Since(s).Round(time.Millisecond), err)
		}()
		files := filepath.Join(vol, "Files")
		n, dirs := 0, 0
		var total int64
		filepath.WalkDir(files, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				dirs++
			} else if fi, err := d.Info(); err == nil {
				n++
				total += fi.Size()
			}
			return nil
		})
		fmt.Printf("walk Files: %d files, %d dirs, %d bytes\n", n, dirs, total)
		for _, probe := range []string{`Windows\System32\cmd.exe`, `Windows\System32\ntdll.dll`} {
			if fi, err := os.Stat(filepath.Join(files, probe)); err == nil {
				fmt.Printf("  %s %d bytes\n", strings.ToLower(probe), fi.Size())
			} else {
				fmt.Printf("  %s: %v\n", probe, err)
			}
		}
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

type cpu struct{ user, kernel time.Duration }

func cpuTimes() cpu {
	var c, e, k, u syscall.Filetime
	h, _ := syscall.GetCurrentProcess()
	if err := syscall.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return cpu{}
	}
	d := func(f syscall.Filetime) time.Duration {
		return time.Duration(int64(f.HighDateTime)<<32|int64(f.LowDateTime)) * 100
	}
	return cpu{user: d(u), kernel: d(k)}
}

func cpuSince(c0 cpu) string {
	c := cpuTimes()
	return fmt.Sprintf("cpu user=%s kernel=%s", (c.user - c0.user).Round(time.Millisecond), (c.kernel - c0.kernel).Round(time.Millisecond))
}
