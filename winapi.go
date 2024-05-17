package dumper

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MEM_PRIVATE = 0x20000
	MEM_MAPPED  = 0x40000
	MEM_IMAGE   = 0x1000000
)

var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procCreateRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procLoadLibraryA             = kernel32.NewProc("LoadLibraryA")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procVirtualQueryEx           = kernel32.NewProc("VirtualQueryEx")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	getSystemInfo                = kernel32.NewProc("GetSystemInfo")
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func (mbi MEMORY_BASIC_INFORMATION) IsReadable() bool {
	if mbi.State != windows.MEM_COMMIT {
		return false
	}

	if mbi.Protect&windows.PAGE_GUARD != 0 {
		return false
	}

	if mbi.Protect&windows.PAGE_READONLY != 0 {
		return true
	}

	if mbi.Protect&windows.PAGE_READWRITE != 0 {
		return true
	}

	if mbi.Protect&windows.PAGE_EXECUTE_READ != 0 {
		return true
	}

	if mbi.Protect&windows.PAGE_EXECUTE_READWRITE != 0 {
		return true
	}

	if mbi.Protect&windows.PAGE_EXECUTE_WRITECOPY != 0 {
		return true
	}

	return false
}

func (mbi MEMORY_BASIC_INFORMATION) IsWritable() bool {
	if mbi.State != windows.MEM_COMMIT {
		return false
	}

	if mbi.Protect&windows.PAGE_GUARD != 0 {
		return false
	}

	if mbi.Protect&windows.PAGE_READWRITE != 0 {
		return true
	}

	if mbi.Protect&windows.PAGE_EXECUTE_READWRITE != 0 {
		return true
	}

	if mbi.Protect&windows.PAGE_EXECUTE_WRITECOPY != 0 {
		return true
	}

	return false
}

type PROCESSENTRY32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CountThreads      uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [windows.MAX_PATH]uint16
}

type SYSTEM_INFO struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

func createToolhelp32Snapshot(flags, processID uint32) (syscall.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(uintptr(flags), uintptr(processID))
	if ret == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
}

func process32Next(snapshot syscall.Handle, pe *PROCESSENTRY32) error {
	ret, _, err := procProcess32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(pe)))
	if ret == 0 {
		return err
	}
	return nil
}

func closeHandle(handle windows.Handle) {
	procCloseHandle.Call(uintptr(handle))
}

func virtualQueryEx(hProcess windows.Handle, lpAddress uintptr) (MEMORY_BASIC_INFORMATION, error) {
	var mbi MEMORY_BASIC_INFORMATION
	ret, _, err := procVirtualQueryEx.Call(
		uintptr(hProcess),
		lpAddress,
		uintptr(unsafe.Pointer(&mbi)),
		uintptr(unsafe.Sizeof(mbi)),
	)
	if ret != uintptr(unsafe.Sizeof(mbi)) {
		return mbi, err
	}
	return mbi, nil
}

func VirtualAllocEx(hProcess windows.Handle, addr uintptr, size, allocType, protect uint32) (uintptr, error) {
	ret, _, err := procVirtualAllocEx.Call(uintptr(hProcess), addr, uintptr(size), uintptr(allocType), uintptr(protect))
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}
