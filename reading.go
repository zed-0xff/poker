package dumper

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ReadProcessMemory(pid uint32, ea uintptr, size int) []byte {
	for region := range Regions(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ) {
		if ea < region.Metadata.BaseAddress || ea >= region.Metadata.BaseAddress+uintptr(region.Metadata.RegionSize) {
			continue
		}

		return region.Read(ea, size)
	}

	if ScriptMode {
		fmt.Printf("[!] failed to read %d bytes at %x\n", size, ea)
		os.Exit(1)
	}

	return nil
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
