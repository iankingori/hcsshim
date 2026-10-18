//go:build windows

// cimprobe reports which CimFS features the host supports.
package main

import (
	"fmt"
	"os"

	"github.com/Microsoft/hcsshim/pkg/cimfs"
)

func main() {
	if len(os.Args) > 1 {
		if err := spike(os.Args[1:]); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		return
	}
	for _, f := range []struct {
		name string
		fn   func() bool
	}{
		{"CimFS", cimfs.IsCimFSSupported},
		{"BlockCim", cimfs.IsBlockCimSupported},
		{"BlockCimWrite", cimfs.IsBlockCimWriteSupported},
		{"BlockCimMount", cimfs.IsBlockCimMountSupported},
		{"MergedCim", cimfs.IsMergedCimSupported},
		{"MergedCimWrite", cimfs.IsMergedCimWriteSupported},
		{"MergedCimMount", cimfs.IsMergedCimMountSupported},
		{"VerifiedCim", cimfs.IsVerifiedCimSupported},
	} {
		fmt.Printf("%-16s %v\n", f.name, f.fn())
	}
}
