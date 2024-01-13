package dumper

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
    "encoding/binary"

	"golang.org/x/sys/windows"
)

const VERSION = "1.0"

var g_si systemInfo
var g_script = false
var g_verbosity = 0
var g_debug = false

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

type Pattern []int // -1 means wildcard

func (p Pattern) String() string {
    s := ""
    for _, c := range p {
        if c == -1 {
            s += "?? "
        } else {
            s += fmt.Sprintf("%02X ", c)
        }
    }
    return strings.TrimSpace(s)
}

func (p Pattern) Find(buffer* []byte) int {
    for i := 0; i < len(*buffer); i++ {
        if p[0] == -1 || int((*buffer)[i]) == p[0] {
            found := true
            for j := 1; j < len(p); j++ {
                if i+j >= len(*buffer) || (p[j] != -1 && int((*buffer)[i+j]) != p[j]) {
                    found = false
                    break
                }
            }
            if found {
                return i
            }
        }
    }
    return -1
}

func parsePattern(src string) Pattern {
    pattern := Pattern{}

    for _, c := range strings.Split(src, " ") {
        // convert each arg from hex to byte
        if c == "?" || c == "??" {
            pattern = append(pattern, -1)
        } else {
            x, err := strconv.ParseUint(string(c), 16, 8)
            if err != nil {
                panic(err)
            }
            pattern = append(pattern, int(x))
        }
    }

    return pattern
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

func createSparseFile(fname string) {
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

// create interface that has methods Start(), Finish() and Write()
type DumpWriter struct {
}

func (dw DumpWriter) Start() {
}

func (dw DumpWriter) Finish() {
}

func (dw DumpWriter) Write(buffer []byte) {
}

func dumpAll(pid uint64) {
	fmt.Printf("[.] Dumping all READABLE regions of PID %d ..\n", pid)

	fname := fmt.Sprintf("pid_%d_sparse.bin", pid)
	totalWritten := 0

	createSparseFile(fname)

	enumRegions(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, func(mbi MEMORY_BASIC_INFORMATION, hProcess windows.Handle) {
		if mbi.isReadable() {
			showRegion(mbi, hProcess)

			buffer := make([]byte, mbi.RegionSize)
			var bytesRead uintptr = mbi.RegionSize

			err := windows.ReadProcessMemory(
				hProcess,
				mbi.BaseAddress,
				&buffer[0],
				mbi.RegionSize,
				&bytesRead,
			)
			if err != nil {
				panic(err)
			}

			f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				panic(err)
			}
			defer f.Close()

			_, err = f.Seek(int64(mbi.BaseAddress), os.SEEK_SET)
			if err != nil {
				panic(err)
			}

			bytesWritten, err := f.Write(buffer[:bytesRead])
			if err != nil {
				panic(err)
			}

			if bytesRead != uintptr(bytesWritten) {
				panic(fmt.Errorf("bytesRead != bytesWritten"))
			}

			totalWritten += bytesWritten
		}
	})

	fmt.Printf("[=] %s (%d bytes)\n", fname, totalWritten)
}

func dumpRegion(pid uint64, target_ea uintptr) {
	fmt.Printf("[.] Dumping region %x of PID %d ..\n", target_ea, pid)

	enumRegions(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, func(mbi MEMORY_BASIC_INFORMATION, hProcess windows.Handle) {
		if mbi.State == windows.MEM_COMMIT && target_ea >= mbi.BaseAddress && target_ea < mbi.BaseAddress+uintptr(mbi.RegionSize) {
			showRegion(mbi, hProcess)

			buffer := make([]byte, mbi.RegionSize)
			var bytesRead uintptr = mbi.RegionSize

			err := windows.ReadProcessMemory(
				hProcess,
				mbi.BaseAddress,
				&buffer[0],
				mbi.RegionSize,
				&bytesRead,
			)
			if err != nil {
				panic(err)
			}
			fname := fmt.Sprintf("%08X.bin", mbi.BaseAddress)

			f, err := os.Create(fname)
			if err != nil {
				panic(err)
			}
			defer f.Close()

			bytesWritten, err := f.Write(buffer[:bytesRead])
			if err != nil {
				panic(err)
			}

			if bytesRead != uintptr(bytesWritten) {
				panic(fmt.Errorf("bytesRead != bytesWritten"))
			}

			fmt.Printf("[=] %s (%d bytes)\n", fname, bytesWritten)
		}
	})
}

func showRegion(mbi MEMORY_BASIC_INFORMATION, hProcess windows.Handle) {
	if mbi.State != windows.MEM_COMMIT {
		return
	}
    if g_verbosity < 0 {
        return
    }

	fmt.Printf(
		"    ba:%12X size:%9X state:%8X type:%8X prot: %4X %s\n",
		mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Type, mbi.Protect, prot2str(mbi.Protect),
	)
}

func enumRegions(pid uint64, openMode uint32, callback func(MEMORY_BASIC_INFORMATION, windows.Handle)) error {
	hProcess, err := openProcess(
		openMode,
		0,
		uint32(pid),
	)
	if err != nil {
		panic(err)
	}
	defer closeHandle(hProcess)

	for ea := g_si.MinimumApplicationAddress; ea < g_si.MaximumApplicationAddress; {
		mbi, err := virtualQueryEx(hProcess, ea)
		if err != nil {
			panic(err)
		}
		if mbi.BaseAddress+uintptr(mbi.RegionSize)-1 > g_si.MaximumApplicationAddress {
			break
		}
		callback(mbi, hProcess)

		ea = mbi.BaseAddress + uintptr(mbi.RegionSize)
	}

	return nil
}

func showRegions(pid uint64) {
	fmt.Printf("[.] Memory regions of PID %d: (only MEM_COMMIT ones)\n", pid)
	enumRegions(pid, windows.PROCESS_QUERY_INFORMATION, showRegion)
}

func findFirstEx(pid uint64, region_type uint32, region_prot uint32, pattern Pattern) []byte {
    buffer := make([]byte, 0x1000)

    found_offset := -1

	enumRegions(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, func(mbi MEMORY_BASIC_INFORMATION, hProcess windows.Handle) {
        if found_offset != -1 {
            return
        }

		if !mbi.isReadable() || mbi.Protect != region_prot || mbi.Type != region_type {
			return
		}

		var bytesRead uintptr = mbi.RegionSize
        if int(mbi.RegionSize) > len(buffer) {
            buffer = make([]byte, mbi.RegionSize)
        }

		err := windows.ReadProcessMemory(
			hProcess,
			mbi.BaseAddress,
			&buffer[0],
			mbi.RegionSize,
			&bytesRead,
		)
		if err != nil {
			panic(err)
		}

        if bytesRead <= 0 {
            return
        }

        found_offset = pattern.Find(&buffer)
	})

    if found_offset == -1 {
        if g_script {
            fmt.Printf("[!] pattern not found: %s\n", pattern)
            os.Exit(1)
        }
        return nil
    } else {
        if g_debug {
            fmt.Printf("[d] found_offset: %x\n", found_offset)
        }
        return buffer[found_offset:found_offset+len(pattern)]
    }
}

func findPattern(pid uint64, pattern Pattern) {
	fmt.Printf("[.] Searching for %d bytes in PID %d ..\n", len(pattern), pid)

	enumRegions(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, func(mbi MEMORY_BASIC_INFORMATION, hProcess windows.Handle) {
		if !mbi.isReadable() {
			return
		}

		buffer := make([]byte, mbi.RegionSize)
		var bytesRead uintptr = mbi.RegionSize

		err := windows.ReadProcessMemory(
			hProcess,
			mbi.BaseAddress,
			&buffer[0],
			mbi.RegionSize,
			&bytesRead,
		)
		if err != nil {
			panic(err)
		}

		if bytesRead <= 0 {
			return
		}

		firstInRegion := true
		ea := mbi.BaseAddress
		foundAny := false
		for i := 0; i < int(bytesRead); i++ {
			if pattern[0] == -1 || int(buffer[i]) == pattern[0] {
				found := true
				for j := 1; j < len(pattern); j++ {
					if i+j >= int(bytesRead) || (pattern[j] != -1 && int(buffer[i+j]) != pattern[j]) {
						found = false
						break
					}
				}
				if found {
					foundAny = true
					if firstInRegion {
						showRegion(mbi, hProcess)
						firstInRegion = false
					}
					fmt.Printf("%19X:", ea+uintptr(i))
					for j := 0; j < 16; j++ {
						if i+j < int(bytesRead) {
							fmt.Printf(" %02x", buffer[i+j])
						} else {
							fmt.Printf("   ")
						}
					}

					fmt.Printf("     |")

					for j := 0; j < 16; j++ {
						if i+j < int(bytesRead) && buffer[i+j] >= 32 && buffer[i+j] <= 126 {
							fmt.Printf("%c", buffer[i+j])
						} else {
							fmt.Printf(" ")
						}
					}

					fmt.Println("|")
				}
			}
		}
		if foundAny {
			fmt.Println()
		}
	})
}

// prints hexdump, 16 bytes per line, with ascii chars on the right
func hexDump(buffer []byte, ea uintptr) {
	for i := 0; i < len(buffer); i += 16 {
		fmt.Printf("%19X:", uintptr(i)+ea)
		for j := 0; j < 16; j++ {
			if i+j < len(buffer) {
				fmt.Printf(" %02x", buffer[i+j])
			} else {
				fmt.Printf("   ")
			}
		}

		fmt.Printf("     |")

		for j := 0; j < 16; j++ {
			if i+j < len(buffer) && buffer[i+j] >= 32 && buffer[i+j] <= 126 {
				fmt.Printf("%c", buffer[i+j])
			} else {
				fmt.Printf(" ")
			}
		}

		fmt.Println("|")
	}
}

func showMem(pid uint64, ea uintptr, size int) {
    data := readMem(pid, ea, size)
    if data != nil {
        hexDump(data, ea)
    }
}

func readMem(pid uint64, ea uintptr, size int) []byte {
    buffer := make([]byte, size)
    done := false

	enumRegions(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, func(mbi MEMORY_BASIC_INFORMATION, hProcess windows.Handle) {
        if done {
            return
        }

		if !mbi.isReadable() {
			return
		}

		if ea >= mbi.BaseAddress && ea < mbi.BaseAddress+uintptr(mbi.RegionSize) {
			showRegion(mbi, hProcess)

			var bytesRead uintptr;

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

    if g_script && !done {
        fmt.Printf("[!] failed to read %d bytes at %x\n", size, ea)
        os.Exit(1)
    }

    if done {
        return buffer
    } else {
        return nil
    }
}

func showProcesses() {
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

func findProcess(processName string) uint64 {
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
			return uint64(pe.ProcessID)
		}

		err := process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}

	return 0
}

func parsePidOrExe(pid_or_exename string) uint64 {
	var pid uint64 = 0
	var err error

	if strings.HasSuffix(pid_or_exename, ".exe") {
		pid = findProcess(pid_or_exename)
		if pid == 0 {
			fmt.Println("Process not found:", os.Args[1])
			os.Exit(1)
		}
	} else {
		pid, err = strconv.ParseUint(pid_or_exename, 10, 32)
		if err != nil {
			fmt.Println("Invalid PID:", pid_or_exename)
			os.Exit(1)
		}
	}
	return pid
}

func usage() {
	fmt.Print(
        "Universal memory patcher/dumper v", VERSION, " by zed_0xff\n",
		"Usage:\n",
		"    dumper ps\n",
		"    dumper <pid_or_exename> list\n",
		"    dumper <pid_or_exename> dump <addr>\n",
		"    dumper <pid_or_exename> dump all\n",
		"    dumper <pid_or_exename> find <bytes>\n",
		"    dumper <pid_or_exename> show <addr> [size]\n",
		"    dumper <pid_or_exename> read <addr> <size>\n",
	)
}

func parseHex(s string, title string) uint64 {
    if strings.HasPrefix(s, "0x") {
        s = s[2:]
    }
    x, err := strconv.ParseUint(s, 16, 64)
    if err != nil {
        fmt.Printf("[?] Invalid %s: %s\n", title, s)
        os.Exit(1)
    }
    return x
}

func pop(args *[]string) string {
    arg := (*args)[0]
    *args = (*args)[1:]
    return arg
}

func run(args []string) []byte {
    if g_debug {
        fmt.Println("[d] run(", args, ")")
    }

	if args[0] == "ps" {
		showProcesses()
		return nil
	}

    arg := pop(&args)
	pid := parsePidOrExe(arg)
	if pid == 0 {
		fmt.Println("Process not found:", arg)
		os.Exit(1)
	}

	if len(args) == 0 {
		showRegions(pid)
		return nil
	}

    arg = strings.ToLower(pop(&args))

    switch arg {
	case "list":
        if len(args) != 0 {
            usage()
            os.Exit(1)
        }
		showRegions(pid)
	case "dump":
		if len(args) == 0 {
			usage()
			os.Exit(1)
		}
		if args[0] == "all" {
			dumpAll(pid)
		} else {
			dumpRegion(pid, uintptr(parseHex(args[0], "address")))
		}
	case "find":
		if len(args) != 1 {
			usage()
			os.Exit(1)
		}
		pattern := parsePattern(strings.Join(args[1:], " "))
		findPattern(pid, pattern)
    case "findfirstex":
		if len(args) < 3 {
			usage()
			os.Exit(1)
		}

        region_type := parseHex(args[0], "region_type")
        region_prot := parseHex(args[1], "region_prot")
		pattern := parsePattern(strings.Join(args[2:], " "))
        result := findFirstEx(pid, uint32(region_type), uint32(region_prot), pattern)
        if !g_script || g_debug {
            if result != nil {
                hexDump(result, 0)
            }
        }
        return result
	case "show":
		if len(args) > 2 {
			usage()
			os.Exit(1)
		}
        size := 0x100
        if len(args) == 2 {
            size = int(parseHex(args[1], "size"))
        }
		ea := uintptr(parseHex(args[0], "address"))
		showMem(pid, ea, size)

    case "read":
        if len(args) != 2 {
            usage()
            os.Exit(1)
        }

        result := readMem(pid, uintptr(parseHex(args[0], "ea")), int(parseHex(args[1], "size")))
        if !g_script {
            if result != nil {
                os.Stdout.Write(result)
            }
        }
        return result
	default:
        fmt.Println("[?] Invalid command:", arg)
		usage()
		os.Exit(1)
	}

    return nil
}
