package poker

import (
	"golang.org/x/sys/windows"
)

func (p *Process) Inject(data []byte) uintptr {
	lp := p.Open(windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE)
	defer lp.Close()

	addr := lp.VirtualAllocEx(0, len(data), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	lp.WriteMemory(addr, data)
	return addr

	// Create Remote Thread
	//	hThread, _, err := procCreateRemoteThread.Call(uintptr(process.Handle), 0, 0, procLoadLibraryA.Addr(), addr, 0, 0)
	//	if err != nil {
	//		panic(fmt.Errorf("CreateRemoteThread failed: %w", err))
	//	}
	//	defer windows.CloseHandle(windows.Handle(hThread))
	//
	//	windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
}
