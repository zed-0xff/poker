package dumper

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ReadProcessMemory(pid uint32, ea uintptr, size int) []byte {
	buffer := make([]byte, size)
	done := false

	EnumProcessRegions(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, func(mbi MEMORY_BASIC_INFORMATION, hProcess windows.Handle) {
		if done {
			return
		}

		if !mbi.isReadable() {
			return
		}

		if ea >= mbi.BaseAddress && ea < mbi.BaseAddress+uintptr(mbi.RegionSize) {
			ShowRegion(mbi, hProcess)

			var bytesRead uintptr

			err := windows.ReadProcessMemory(
				hProcess,
				ea,
				&buffer[0],
				uintptr(size),
				&bytesRead,
			)
			if err != nil {
				panic(err)
			}

			done = int(bytesRead) == size
		}
	})

	if ScriptMode && !done {
		fmt.Printf("[!] failed to read %d bytes at %x\n", size, ea)
		os.Exit(1)
	}

	if done {
		return buffer
	} else {
		return nil
	}
}

func ReadUInt32(pid uint32, ea uintptr) uint32 {
	buffer := ReadProcessMemory(pid, ea, 4)
	if buffer != nil {
		return *(*uint32)(unsafe.Pointer(&buffer[0]))
	} else {
		msg := fmt.Sprintf("failed to read 4 bytes at %x", ea)
		if ScriptMode {
			fmt.Printf("[!] %s\n", msg)
			os.Exit(1)
		} else {
			panic(msg)
		}
		return 0
	}
}

func ReadUInt64(pid uint32, ea uintptr) uint64 {
	buffer := ReadProcessMemory(pid, ea, 8)
	if buffer != nil {
		return *(*uint64)(unsafe.Pointer(&buffer[0]))
	} else {
		msg := fmt.Sprintf("failed to read 8 bytes at %x", ea)
		if ScriptMode {
			fmt.Printf("[!] %s\n", msg)
			os.Exit(1)
		} else {
			panic(msg)
		}
		return 0
	}
}
