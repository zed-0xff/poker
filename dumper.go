package dumper

import (
	"fmt"
	"os"
    "strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const Version = "0.3.0"

var ScriptMode = false
var Verbosity = 0
var g_buffer = []byte{}

func prot2str(prot uint32) string {
	var s string

	if prot&windows.PAGE_READONLY != 0 {
		s += "[r--]"
	}
	if prot&windows.PAGE_READWRITE != 0 {
		s += "[rw-]"
	}
	if prot&windows.PAGE_WRITECOPY != 0 {
		s += "[-w-][writecopy]"
	}
	if prot&windows.PAGE_EXECUTE != 0 {
		s += "[--x]"
	}
	if prot&windows.PAGE_EXECUTE_READ != 0 {
		s += "[r-x]"
	}
	if prot&windows.PAGE_EXECUTE_READWRITE != 0 {
		s += "[rwx]"
	}
	if prot&windows.PAGE_EXECUTE_WRITECOPY != 0 { // is it rwx ?
		s += "[rwx][writecopy]"
	}

	if prot&windows.PAGE_GUARD != 0 {
		s += "[guard]"
	}
	if prot&windows.PAGE_NOCACHE != 0 {
		s += "[nocache]"
	}
	if prot&windows.PAGE_WRITECOMBINE != 0 {
		s += "[writecombine]"
	}

	if s == "" {
		s = "[   ]"
	}

	return s
}

func CreateSparseFile(fname string) {
	// Step 1: Create a new file
	file, err := os.Create(fname)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Step 2: Mark the file as sparse
	var bytesReturned uint32
	fsctlSetSparse := uint32(0x000900c4)
	err = syscall.DeviceIoControl(syscall.Handle(file.Fd()), fsctlSetSparse, nil, 0, nil, 0, &bytesReturned, nil)
	if err != nil {
		panic(err)
	}
}

func WriteFileEx(fname string, data []byte, mode int, offset int) error {
	f, err := os.OpenFile(fname, mode, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if offset > 0 {
		_, err = f.Seek(int64(offset), os.SEEK_SET)
		if err != nil {
			return err
		}
	}

	bytesWritten, err := f.Write(data)
	if err != nil {
		return err
	}

	if bytesWritten != len(data) {
		return fmt.Errorf("bytesRead != bytesWritten")
	}

	return nil
}

func WriteFile(fname string, data []byte) error {
	return WriteFileEx(fname, data, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
}

func (process *Process) DumpAll() {
	fmt.Printf("[.] Dumping all READABLE regions of PID %d ..\n", process.Pid)

	fname := fmt.Sprintf("pid_%d_sparse.bin", process.Pid)
	totalWritten := 0

	CreateSparseFile(fname)
	for _, region := range process.Regions() {
		if !region.IsReadable() {
			continue
		}
		region.Show()
		WriteFileEx(fname, region.ReadAll(), os.O_WRONLY|os.O_CREATE, int(region.MBI.BaseAddress))
		totalWritten += int(region.MBI.RegionSize)
	}
	fmt.Printf("[=] %s (%d bytes)\n", fname, totalWritten)
}

func (process *Process) DumpRegion(target_ea uintptr) {
	fmt.Printf("[.] Dumping region %x of PID %d ..\n", target_ea, process.Pid)

	for _, region := range process.Regions() {
		if target_ea < region.MBI.BaseAddress || target_ea >= region.MBI.BaseAddress+uintptr(region.MBI.RegionSize) {
			continue
		}

		region.Show()

		fname := fmt.Sprintf("%08X.bin", region.MBI.BaseAddress)
		err := WriteFile(fname, region.ReadAll())
		if err != nil {
			panic(err)
		}
		fmt.Printf("[=] %s (%d bytes)\n", fname, region.MBI.RegionSize)
	}
}

func (process *Process) ShowRegions() {
	fmt.Printf("[.] Memory regions of PID %d: (only MEM_COMMIT ones)\n", process.Pid)
	for _, region := range process.Regions() {
		if !region.IsCommitted() && Verbosity < 1 {
			continue
		}

		region.Show()
	}
}

func (process *Process) ShowAllRegions() {
	fmt.Printf("[.] Memory regions of PID %d:\n", process.Pid)
	for _, region := range process.Regions() {
		region.Show()
	}
}

// zero region_type or region_prot means ANY READABLE region
func (process *Process) FindFirstEx(region_type uint32, region_prot uint32, pattern Pattern) []byte {
	for _, region := range process.Regions() {
		if !region.IsReadable() {
			continue
		}
		if region_type != 0 && region.MBI.Type != region_type {
			continue
		}
		if region_prot != 0 && region.MBI.Protect != region_prot {
			continue
		}

		data := region.ReadAll()
		offset := pattern.Find(data)
		if offset >= 0 {
			if Verbosity > 0 {
				region.Show()
				ea := uintptr(offset) + region.MBI.BaseAddress
				fmt.Printf("[=] Found:\n")
				HexDump(data[offset:offset+pattern.Length()], ea)
			}
			return data[offset : offset+pattern.Length()]
		}
	}

	if ScriptMode {
		fmt.Printf("[!] pattern not found: %s\n", pattern)
		os.Exit(1)
	}
	return nil
}

// generator
func (process *Process) FindEach(pattern Pattern) chan *byte {
	if Verbosity > 0 {
		fmt.Printf("[.] Searching for %d bytes in PID %d ..\n", pattern.Length(), process.Pid)
	}

	ch := make(chan *byte)
	go func() {
		for _, region := range process.Regions() {
			if !region.IsReadable() {
				continue
			}

			data := region.ReadAll()
			offset := pattern.Find(data)
			if offset >= 0 {
				ch <- &data[offset]
			}
		}
		close(ch)
	}()

	return ch
}

func ShowProcesses() {
	var pe PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))

	snapshot, err := createToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		fmt.Println("Error creating snapshot:", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	for {
		processName := windows.UTF16ToString(pe.ExeFile[:])

		fmt.Printf("%8d %s\n", pe.ProcessID, processName)

		err := process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}
}

// returns PID or 0 if not found
func FindProcess(processName string) uint32 {
	processName = strings.ToLower(processName)

	var pe PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))

	snapshot, err := createToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		fmt.Println("Error creating snapshot:", err)
		return 0
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	for {
		if strings.ToLower(windows.UTF16ToString(pe.ExeFile[:])) == processName {
			return pe.ProcessID
		}

		err := process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}

	return 0
}

func ParsePidOrExe(pid_or_exename string) uint32 {
	var pid uint32 = 0

	if strings.HasSuffix(pid_or_exename, ".exe") {
		pid = FindProcess(pid_or_exename)
		if pid == 0 {
			panic("Process not found: " + pid_or_exename)
		}
	} else {
		val, err := strconv.ParseUint(pid_or_exename, 10, 32)
		if err != nil {
			panic("Invalid PID:" + pid_or_exename)
		}
		pid = uint32(val)
	}
	return pid
}

func SetScriptMode(value bool) {
	if value {
		ScriptMode = true
		if Verbosity >= 0 {
			Verbosity = -1
		}
	} else {
		ScriptMode = false
		if Verbosity < 0 {
			Verbosity = 0
		}
	}
}
