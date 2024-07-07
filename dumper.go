package poker

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const Version = "0.4.0 alpha"

var ScriptMode = false
var Verbosity = 0
var g_buffer = []byte{}

func PtrFmtSize() int {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return 12
	} else {
		return 8
	}
}

func prot2ext(prot uint32) string {
	if prot&windows.PAGE_READONLY != 0 {
		return "r"
	}
	if prot&windows.PAGE_READWRITE != 0 {
		return "rw"
	}
	if prot&windows.PAGE_WRITECOPY != 0 {
		return "rw"
	}
	if prot&windows.PAGE_EXECUTE != 0 {
		return "x"
	}
	if prot&windows.PAGE_EXECUTE_READ != 0 {
		return "rx"
	}
	if prot&windows.PAGE_EXECUTE_READWRITE != 0 {
		return "rwx"
	}
	if prot&windows.PAGE_EXECUTE_WRITECOPY != 0 { // is it rwx ?
		return "rwx"
	}
	return "bin"
}

func prot2str(prot uint32) string {
	var s string

	if prot&windows.PAGE_READONLY != 0 {
		s += "[r--]"
	}
	if prot&windows.PAGE_READWRITE != 0 {
		s += "[rw-]"
	}
	if prot&windows.PAGE_WRITECOPY != 0 {
		s += "[rw-][writecopy]"
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

func (process *Process) DumpRange(start uintptr, end uintptr, sparse bool) {
	if start == 0 && end == ^uintptr(0) {
		fmt.Printf("[.] Dumping all READABLE regions of PID %d ..\n", process.Pid)
	} else {
		fmt.Printf("[.] Dumping range %x-%x of PID %d ..\n", start, end, process.Pid)
	}

	fname := ""
	if sparse {
		fname = fmt.Sprintf("pid_%d_sparse.bin", process.Pid)
		CreateSparseFile(fname)
	}

	totalWritten := 0

	for _, region := range process.Regions() {
		if !region.IsReadable() {
			continue
		}
		if start != 0 && (region.MBI.BaseAddress+uintptr(region.MBI.RegionSize)) < start {
			continue
		}
		if end != ^uintptr(0) && region.MBI.BaseAddress >= end {
			continue
		}

		region.Show()

		if sparse {
			WriteFileEx(fname, region.ReadAll(), os.O_WRONLY|os.O_CREATE, int(region.MBI.BaseAddress))
		} else {
			fname := fmt.Sprintf("%0*x.%s", PtrFmtSize(), region.MBI.BaseAddress, prot2ext(region.MBI.Protect))
			if region.Module != nil && region.Module.Name != "" {
				moduleName := region.Module.Name
				moduleName = strings.Replace(moduleName, ".dll", "", -1)
				moduleName = strings.Replace(moduleName, ".exe", "", -1)
				if moduleName != "" {
					fname = fmt.Sprintf("%0*x_%s.%s", PtrFmtSize(), region.MBI.BaseAddress, moduleName, prot2ext(region.MBI.Protect))
				}
			}
			err := WriteFile(fname, region.ReadAll())
			if err != nil {
				panic(err)
			}
		}
		totalWritten += int(region.MBI.RegionSize)
	}
	fmt.Printf("[=] %s (%d bytes)\n", fname, totalWritten)
}

// enumerate regions, and call callback for each region, if callback returns true - dump the region
func (process *Process) DumpIf(dumpDir string, callback func(*Region, []byte) bool) int {
	totalWritten := 0
	dir_created := false

	for _, region := range process.Regions() {
		if !region.IsReadable() {
			continue
		}

        // first call to callback to check if we should dump this region, without reading it
		if !callback(&region, nil) {
			continue
		}

		data := region.ReadAll()
        if data == nil || len(data) == 0 {
            continue
        }

		if !callback(&region, data) {
			continue
		}

		region.Show()

		fname := fmt.Sprintf("%0*x.%s", PtrFmtSize(), region.MBI.BaseAddress, prot2ext(region.MBI.Protect))
		if region.Module != nil && region.Module.Name != "" {
			moduleName := region.Module.Name
			moduleName = strings.Replace(moduleName, ".dll", "", -1)
			moduleName = strings.Replace(moduleName, ".exe", "", -1)
			if moduleName != "" {
				fname = fmt.Sprintf("%0*x_%s.%s", PtrFmtSize(), region.MBI.BaseAddress, moduleName, prot2ext(region.MBI.Protect))
			}
		}
		if !dir_created {
			os.MkdirAll(dumpDir, 0755)
			dir_created = true
		}
		fname = filepath.Join(dumpDir, fname)
		err := WriteFile(fname, data)
		if err != nil {
			panic(err)
		}
		totalWritten += int(region.MBI.RegionSize)
	}
	return totalWritten
}

func (process *Process) DumpRegion(target_ea uintptr) {
	fmt.Printf("[.] Dumping region %x of PID %d ..\n", target_ea, process.Pid)

	for _, region := range process.Regions() {
		if target_ea < region.MBI.BaseAddress || target_ea >= region.MBI.BaseAddress+uintptr(region.MBI.RegionSize) {
			continue
		}

		region.Show()

		fname := fmt.Sprintf("%0*x.bin", PtrFmtSize(), region.MBI.BaseAddress)
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
func (process *Process) FindFirstEx(region_type uint32, region_prot uint32, pattern Pattern) uintptr {
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
			return uintptr(offset) + region.MBI.BaseAddress
		}
	}

	if ScriptMode {
		fmt.Printf("[!] pattern not found: %s\n", pattern)
		os.Exit(1)
	}
	return 0
}

// generator
func (process *Process) FindEach(pattern Pattern) chan uintptr {
	if Verbosity > 0 {
		fmt.Printf("[.] Searching for %d bytes in PID %d ..\n", pattern.Length(), process.Pid)
	}

	ch := make(chan uintptr)
	go func() {
		for _, region := range process.Regions() {
			if !region.IsReadable() {
				continue
			}

			data := region.ReadAll()
			index := 0
			for {
				// Find method now needs to handle repeated searches, starting from the index
				offset := pattern.Find(data[index:])
				if offset < 0 {
					break
				}
				// Calculate the real match address based on the base address and offset
				matchAddress := region.MBI.BaseAddress + uintptr(index+offset)
				ch <- matchAddress
				// Move index past the current match for subsequent searches
				index += offset + 1
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
