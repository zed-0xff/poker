package dumper

import (
	"fmt"

	"golang.org/x/sys/windows"
)

type Region struct {
	MBI     MEMORY_BASIC_INFORMATION
	Process Process
	Module  *Module
}

func (r *Region) IsImage() bool {
	return r.MBI.Type == MEM_IMAGE
}

func (r *Region) IsMapped() bool {
	return r.MBI.Type == MEM_MAPPED
}

func (r *Region) IsPrivate() bool {
	return r.MBI.Type == MEM_PRIVATE
}

func (r *Region) IsCommitted() bool {
	return r.MBI.State == windows.MEM_COMMIT
}

func (r *Region) IsReadable() bool {
	return r.MBI.IsReadable()
}

func (r *Region) Show() {
	if Verbosity < 0 {
		return
	}

	moduleName := ""
	if r.Module != nil {
		moduleName = r.Module.Name
	}

	fmt.Printf(
		"    ba:%12X size:%12X state:%8X type:%8X prot: %4X %s %s\n",
		r.MBI.BaseAddress, r.MBI.RegionSize, r.MBI.State, r.MBI.Type, r.MBI.Protect, prot2str(r.MBI.Protect), moduleName,
	)
}

func (r *Region) ReadAll() []byte {
	return r.Read(r.MBI.BaseAddress, r.MBI.RegionSize)
}

func (r *Region) Read(ea, size uintptr) []byte {
	return r.Process.ReadMemory(ea, size)
}
