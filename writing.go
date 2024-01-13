package dumper

import (
	"golang.org/x/sys/windows"
)

// writes only to writable regions
func WriteProcessMemory(pid uint32, ea uintptr, buffer []byte) error {
	hProcess, err := openProcess(windows.PROCESS_VM_WRITE, 0, pid)
	if err != nil {
		return err
	}
	defer closeHandle(hProcess)

	var bytesWritten uintptr
	size := len(buffer)

	err = windows.WriteProcessMemory(
		hProcess,
		ea,
		&buffer[0],
		uintptr(size),
		&bytesWritten,
	)

	if err != nil {
		return err
	}

	return nil
}

func WriteUInt32(pid uint32, ea uintptr, value uint32) error {
	buffer := make([]byte, 4)
	buffer[0] = byte(value)
	buffer[1] = byte(value >> 8)
	buffer[2] = byte(value >> 16)
	buffer[3] = byte(value >> 24)
	return WriteProcessMemory(pid, ea, buffer)
}

func WriteUInt64(pid uint32, ea uintptr, value uint64) error {
	buffer := make([]byte, 8)
	buffer[0] = byte(value)
	buffer[1] = byte(value >> 8)
	buffer[2] = byte(value >> 16)
	buffer[3] = byte(value >> 24)
	buffer[4] = byte(value >> 32)
	buffer[5] = byte(value >> 40)
	buffer[6] = byte(value >> 48)
	buffer[7] = byte(value >> 56)
	return WriteProcessMemory(pid, ea, buffer)
}
