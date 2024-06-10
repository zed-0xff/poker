package dumper

import (
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFF

type Process struct {
	Handle windows.Handle
	Pid    uint32
	Access uint32
    suspended bool
}

func OpenProcess(pid, access uint32) *Process {
	handle, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		panic(fmt.Errorf("OpenProcess: %w", err))
	}
	return &Process{
		Handle: handle,
		Pid:    pid,
		Access: access,
	}
}

func StartProcess(exe string) *Process {
    commandLine, _ := windows.UTF16PtrFromString(exe)
    var startupInfo windows.StartupInfo
    var processInfo windows.ProcessInformation
    startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
    creationFlags := uint32(windows.CREATE_SUSPENDED)

    err := windows.CreateProcess(
        nil,                       // Application name
        commandLine,               // Command line
        nil,                       // Process security attributes
        nil,                       // Primary thread security attributes
        false,                     // Handles are not inherited
        creationFlags,             // Creation flags
        nil,                       // Use parent's environment
        nil,                       // Use parent's current directory
        &startupInfo,              // Pointer to STARTUPINFO
        &processInfo,              // Pointer to PROCESS_INFORMATION
    )
    if err != nil {
        panic(err)
    }

    return &Process{
        Handle: processInfo.Process,
        Pid:    processInfo.ProcessId,
        Access: PROCESS_ALL_ACCESS,
        suspended: true,
    }
}

func (p *Process) IsSuspended() bool {
    return p.suspended
}

// reopen if the process is not already opened with the given access rights
func (p *Process) MaybeReopen(access uint32) *Process {
	if p.Access&access == access {
		return p
	}
	return p.Open(access)
}

// returns new Process object with the given access rights, inheriting the handle from the existing one
func (p *Process) Open(access uint32) *Process {
	handle, err := windows.OpenProcess(access, false, p.Pid)
	if err != nil {
		panic(fmt.Errorf("OpenProcess: %w", err))
	}
	return &Process{
		Handle: handle,
		Pid:    p.Pid,
		Access: access,
	}
}

func utf16PtrFromString(s string) *uint16 {
	utf16List := utf16.Encode([]rune(s + "\x00")) // Null-terminated
	return &utf16List[0]
}

type CreateProcessOption func(*createProcessOptions)

func WithFlags(flags uint32) CreateProcessOption {
	return func(proc *createProcessOptions) {
		proc.flags = flags
	}
}

type createProcessOptions struct {
	flags uint32
}

func CreateProcess(path string, args []string, opts ...CreateProcessOption) Process {
	applicationName := utf16PtrFromString(path)
	commandLineStr := path + " " + strings.Join(args, " ")
	commandLine := utf16PtrFromString(commandLineStr)

	proc := &createProcessOptions{}
	for _, opt := range opts {
		opt(proc)
	}

	var startupInfo windows.StartupInfo
	var processInformation windows.ProcessInformation

	err := windows.CreateProcess(
		applicationName,
		commandLine,
		nil,        // ProcessAttributes
		nil,        // ThreadAttributes
		false,      // InheritHandles
		proc.flags, // CreationFlags
		nil,        // Environment
		nil,        // CurrentDirectory
		&startupInfo,
		&processInformation,
	)
	if err != nil {
		panic(fmt.Errorf("CreateProcess failed: %v", err))
	}

	return Process{
		Handle: processInformation.Process,
		Pid:    processInformation.ProcessId,
		Access: windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_TERMINATE | windows.SYNCHRONIZE,
	}
}

// resumes a suspended process by resuming all of its threads.
func (p *Process) Resume() {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		panic(fmt.Errorf("CreateToolhelp32Snapshot: %w", err))
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err = windows.Thread32First(snapshot, &te); err != nil {
		panic(fmt.Errorf("Thread32First: %w", err))
	}

	for {
		if te.OwnerProcessID == p.Pid {
			th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
			if err != nil {
				panic(fmt.Errorf("OpenThread: %w", err))
			}
			_, err = windows.ResumeThread(th)
			if err != nil {
				panic(fmt.Errorf("ResumeThread: %w", err))
			}
			windows.CloseHandle(th)
		}

		if err = windows.Thread32Next(snapshot, &te); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			panic(fmt.Errorf("Thread32Next: %w", err))
		}
	}

    p.suspended = false
}

// closes the process handle, but does not terminate the process
func (p *Process) Close() {
	if p.Handle == 0 {
		return // Handle already closed or never opened
	}
	err := windows.CloseHandle(p.Handle)
	if err != nil {
		panic(fmt.Errorf("failed to close process handle: %w", err))
	}
	p.Handle = 0 // Reset handle to indicate it's closed
}

func (p *Process) VirtualAllocEx(addr uintptr, size int, allocType uint32, protect uint32) uintptr {
	ret, _, err := procVirtualAllocEx.Call(uintptr(p.Handle), addr, uintptr(size), uintptr(allocType), uintptr(protect))
	if ret == 0 {
		panic(fmt.Errorf("VirtualAllocEx: %w", err))
	}
	return ret
}

func (p *Process) VirtualQueryEx(addr uintptr) *MEMORY_BASIC_INFORMATION {
	var mbi MEMORY_BASIC_INFORMATION
	ret, _, _ := procVirtualQueryEx.Call(
		uintptr(p.Handle),
		addr,
		uintptr(unsafe.Pointer(&mbi)),
		uintptr(unsafe.Sizeof(mbi)),
	)
	if ret != uintptr(unsafe.Sizeof(mbi)) {
		return nil
		//panic(fmt.Errorf("VirtualQueryEx: %w", err))
	}
	return &mbi
}

// changes the protection on a region of memory in the process.
func (p *Process) VirtualProtectEx(address uintptr, size uintptr, newProtect uint32) (oldProtect uint32) {
	var sysInfo SYSTEM_INFO
	getSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))

	// Align the address down to the nearest multiple of the system's allocation granularity.
	pageMask := uintptr(sysInfo.PageSize - 1)
	alignedAddress := address & ^pageMask
	endAddress := (address + uintptr(size) + pageMask) & ^pageMask
	adjustedSize := endAddress - alignedAddress

	err := windows.VirtualProtectEx(p.Handle, alignedAddress, adjustedSize, newProtect, &oldProtect)
	if err != nil {
		panic(fmt.Errorf("VirtualProtectEx: %w", err))
	}

	return oldProtect
}

func (p *Process) Regions() []Region {
	var si SYSTEM_INFO
	getSystemInfo.Call(uintptr(unsafe.Pointer(&si)))
	if Verbosity > 1 {
		fmt.Printf("[d] MinimumApplicationAddress=%x, MaximumApplicationAddress=%x\n", si.MinimumApplicationAddress, si.MaximumApplicationAddress)
	}

	lp := p.MaybeReopen(windows.PROCESS_QUERY_INFORMATION)
	if lp != p {
		defer lp.Close()
	}

	regions := make([]Region, 0, 0x100)
	modules := p.Modules()

	for ea := uintptr(0); ea < si.MaximumApplicationAddress; {
		mbi := lp.VirtualQueryEx(ea)
		if mbi == nil {
			break
		}
		regions = append(regions, Region{Process: *lp, MBI: *mbi})
		ea += uintptr(mbi.RegionSize)
	}

	for i := range regions {
		for j := range modules {
			if regions[i].MBI.BaseAddress == modules[j].BaseOfDll || (regions[i].MBI.BaseAddress > modules[j].BaseOfDll && regions[i].MBI.BaseAddress < modules[j].BaseOfDll+uintptr(modules[j].SizeOfImage)) {
				regions[i].Module = &modules[j]
				break
			}
		}
	}

	return regions
}

func (p *Process) Modules() []Module {
	var modules []Module
	var err error

	lp := p.MaybeReopen(windows.PROCESS_QUERY_INFORMATION)
	if lp != p {
		defer lp.Close()
	}

	var needed uint32

	err = windows.EnumProcessModulesEx(lp.Handle, nil, 0, &needed, windows.LIST_MODULES_ALL)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == windows.ERROR_PARTIAL_COPY && needed == 0 {
				// process is not yet initialized OR started in a suspended state
				return modules
			}
		}
		panic(fmt.Errorf("EnumProcessModulesEx: %w [needed=%d]", err, needed))
	}

	numModules := int(needed) / int(unsafe.Sizeof(windows.Handle(0)))
	hModules := make([]windows.Handle, numModules)
	err = windows.EnumProcessModulesEx(lp.Handle, &hModules[0], needed, &needed, windows.LIST_MODULES_ALL)
	if err != nil {
		panic(fmt.Errorf("EnumProcessModulesEx: %w [needed=%d]", err, needed))
	}

	for i := 0; i < numModules; i++ {
		var modName [windows.MAX_PATH]uint16
		windows.GetModuleBaseName(lp.Handle, hModules[i], &modName[0], windows.MAX_PATH)

		var modInfo windows.ModuleInfo
		err = windows.GetModuleInformation(lp.Handle, hModules[i], &modInfo, uint32(unsafe.Sizeof(modInfo)))
		if err != nil {
			continue // or handle the error in another way
		}

		modules = append(modules, Module{
			BaseOfDll:   modInfo.BaseOfDll,
			SizeOfImage: modInfo.SizeOfImage,
			EntryPoint:  modInfo.EntryPoint,
			Name:        windows.UTF16PtrToString(&modName[0]),
		})
	}

	return modules
}

