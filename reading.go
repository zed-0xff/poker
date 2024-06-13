package poker

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (p *Process) ReadMemory(ea, size uintptr) []byte {
	lp := p.MaybeReopen(windows.PROCESS_VM_READ)
	if lp != p {
		defer lp.Close()
	}

	var bytesRead uintptr = uintptr(size)
	buf := make([]byte, size)
	err := windows.ReadProcessMemory(
		lp.Handle,
		ea,
		&buf[0],
		size,
		&bytesRead,
	)
	if err != nil {
		panic(fmt.Errorf("ReadProcessMemory: %v", err))
	}

	return buf[:bytesRead]
}

func (p *Process) ReadUInt32(ea uintptr) uint32 {
	buf := p.ReadMemory(ea, 4)
	return *(*uint32)(unsafe.Pointer(&buf[0]))
}

func (p *Process) ReadUInt64(ea uintptr) uint64 {
	buf := p.ReadMemory(ea, 8)
	return *(*uint64)(unsafe.Pointer(&buf[0]))
}
