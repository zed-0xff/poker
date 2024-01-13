package dumper

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procVirtualQueryEx           = kernel32.NewProc("VirtualQueryEx")
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

func (mbi MEMORY_BASIC_INFORMATION) isReadable() bool {
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

func (mbi MEMORY_BASIC_INFORMATION) isWritable() bool {
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

type systemInfo struct {
	ProcessorArchitecture     uint16
	_                         uint16
	PageSize                  uint32
	_                         [3]uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	_                         uint32
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

func openProcess(dwDesiredAccess uint32, bInheritHandle uint32, dwProcessId uint32) (windows.Handle, error) {
	ret, _, err := procOpenProcess.Call(
		uintptr(dwDesiredAccess),
		uintptr(bInheritHandle),
		uintptr(dwProcessId),
	)
	if ret == 0 {
		return windows.Handle(0), err
	}
	return windows.Handle(ret), nil
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
