package dumper

import (
	"fmt"

	"golang.org/x/sys/windows"
)

type Region struct {
	ProcessHandle windows.Handle
	Metadata      MEMORY_BASIC_INFORMATION
}

func (r Region) IsCommitted() bool {
	return r.Metadata.State == windows.MEM_COMMIT
}

func (r Region) IsReadable() bool {
	return r.Metadata.IsReadable()
}

func (r Region) Show() {
	if Verbosity < 0 {
		return
	}

	fmt.Printf(
		"    ba:%12X size:%9X state:%8X type:%8X prot: %4X %s\n",
		r.Metadata.BaseAddress, r.Metadata.RegionSize, r.Metadata.State, r.Metadata.Type, r.Metadata.Protect, prot2str(r.Metadata.Protect),
	)
}

func (r Region) ReadAll() []byte {
	return r.Read(r.Metadata.BaseAddress, int(r.Metadata.RegionSize))
}

func (r Region) Read(ea uintptr, size int) []byte {
	if size > len(g_buffer) {
		g_buffer = make([]byte, size)
	}

	var bytesRead uintptr = uintptr(size)
	err := windows.ReadProcessMemory(
		r.ProcessHandle,
		ea,
		&g_buffer[0],
		uintptr(size),
		&bytesRead,
	)
	if err != nil {
		panic(err)
	}

	return g_buffer[:bytesRead]
}
