package poker

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func (p *Process) WriteMemory(addr uintptr, data []byte) {
	lp := p.MaybeReopen(windows.PROCESS_VM_WRITE | windows.PROCESS_VM_OPERATION)
	if lp != p {
		defer lp.Close()
	}

	mbi := lp.VirtualQueryEx(addr)

	if !mbi.IsWritable() {
		oldProtect := lp.VirtualProtectEx(addr, uintptr(len(data)), windows.PAGE_EXECUTE_READWRITE)
		defer lp.VirtualProtectEx(addr, uintptr(len(data)), oldProtect)
	}

	var bytesWritten uintptr

	err := windows.WriteProcessMemory(
		lp.Handle,
		addr,
		&data[0],
		uintptr(len(data)),
		&bytesWritten,
	)

	if err != nil {
		panic(fmt.Errorf("WriteProcessMemory: %v", err))
	}
}

func (p *Process) WriteByte(ea uintptr, value byte) {
	buffer := make([]byte, 1)
	buffer[0] = value
	p.WriteMemory(ea, buffer)
}

func (p *Process) WriteUInt32(ea uintptr, value uint32) {
	buffer := make([]byte, 4)
	buffer[0] = byte(value)
	buffer[1] = byte(value >> 8)
	buffer[2] = byte(value >> 16)
	buffer[3] = byte(value >> 24)
	p.WriteMemory(ea, buffer)
}

func (p *Process) WriteUInt64(ea uintptr, value uint64) {
	buffer := make([]byte, 8)
	buffer[0] = byte(value)
	buffer[1] = byte(value >> 8)
	buffer[2] = byte(value >> 16)
	buffer[3] = byte(value >> 24)
	buffer[4] = byte(value >> 32)
	buffer[5] = byte(value >> 40)
	buffer[6] = byte(value >> 48)
	buffer[7] = byte(value >> 56)
	p.WriteMemory(ea, buffer)
}
