package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/md5"

	"github.com/zed-0xff/poker"
	"golang.org/x/sys/windows"
)

type Command struct {
	Func    func(args []string)
	MinArgs int
	MaxArgs int
}

var g_commands = make(map[string]Command)
var g_sparse = false
var g_wait = false
var g_needResume = false
var g_pid uint32 = 0
var g_process *poker.Process = nil

var g_rangeStart uintptr = 0
var g_rangeEnd uintptr = 0
var g_uniq bool = false

// extras:
//   - '_' can be used as a visual separator
//   - '+' can be used for basic arithmetics
func parseHex(s string, title string) uint64 {
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}

	s = strings.ReplaceAll(s, "_", "")
	var result uint64

	for _, part := range strings.Split(s, "+") {
		val, err := strconv.ParseUint(part, 16, 64)
		if err != nil {
			fmt.Printf("[?] Invalid %s: %s\n", title, s)
			os.Exit(1)
		}
		result += val
	}

	return result
}

func registerCommand(name string, minArgs int, maxArgs int, function func(args []string)) {
	g_commands[name] = Command{
		Func:    function,
		MinArgs: minArgs,
		MaxArgs: maxArgs,
	}
}

// TODO: split functionality
func registerFlag(name string, minArgs int, maxArgs int, function func(args []string)) {
	registerCommand(name, minArgs, maxArgs, function)
}

func ps(args []string) {
	poker.ShowProcesses()
}

func savePid(args []string) {
	spid := args[0]
	val, err := strconv.ParseUint(spid, 10, 32)
	if err != nil {
		panic("Invalid PID: " + spid)
	}
	g_pid = uint32(val)
}

func exe2pid(args []string) {
	exe := args[0]
	wait_message_shown := false

	for {
		pid := poker.FindProcess(exe)
		if pid == 0 {
			if g_wait {
				if !wait_message_shown {
					wait_message_shown = true
					fmt.Println("[.] Waiting for process:", exe)
				}
				time.Sleep(1 * time.Millisecond)
			} else {
				fmt.Println("Process not found:", exe)
				os.Exit(1)
			}
		} else {
			g_pid = pid
			break
		}
	}
}

func openProcess() *poker.Process {
	if g_process == nil {
		g_process = poker.OpenProcess(g_pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ)
	}
	return g_process
}

func regions(args []string) {
	openProcess().ShowRegions()
}

func dump(args []string) {
	process := openProcess()

	dumpDir, _ := findUnusedDumpDir()
	os.Mkdir(dumpDir, 0755)
	os.Chdir(dumpDir)

	if len(args) == 0 || args[0] == "all" {
		// dump all
		process.DumpRange(uintptr(0), ^uintptr(0), g_sparse)

	} else if strings.Contains(args[0], "..") {
		addresses := strings.Split(args[0], "..")
		start := uintptr(parseHex(addresses[0], "start"))
		end := uintptr(parseHex(addresses[1], "end"))

		process.DumpRange(start, end, g_sparse)
	} else {
		process.DumpRegion(uintptr(parseHex(args[0], "address")))
	}

	os.Chdir("..")
}

func rangesOverlap(start1, end1, start2, end2 uintptr) bool {
	return start1 <= end2 && start2 <= end1
}

// find first unused dump directory
func findUnusedDumpDir() (string, int) {
	iDir := 0
	var dumpDir string

	for {
		dumpDir = fmt.Sprintf("dump_%d_%04x", g_pid, iDir)
		if _, err := os.Stat(dumpDir); os.IsNotExist(err) {
			break
		}
		iDir++
	}

	return dumpDir, iDir
}

// 1st arg - number of dumps,     default: infinite
// 2nd arg - delay between dumps, default: 1ms
func diffdump(args []string) {
	maxDumps := -1
	delay := 1

	if len(args) > 0 {
		maxDumps, _ = strconv.Atoi(args[0])
		if len(args) > 1 {
			delay, _ = strconv.Atoi(args[1])
		}
	}

	uniqHashes := make(map[[16]byte]bool)
	hashes := make(map[uintptr][]byte)
	var hash []byte

	_, iDir := findUnusedDumpDir()
	nDumps := 0
	process := openProcess()
	for {
		dumpDir := fmt.Sprintf("dump_%d_%04x", process.Pid, iDir)

		nBytesDumped := process.DumpIf(dumpDir, func(region *poker.Region, data []byte) bool {
			// fast callback, without the data, only for region validation
			if data == nil {
				return g_rangeStart == 0 || rangesOverlap(region.MBI.BaseAddress, region.MBI.BaseAddress+region.MBI.RegionSize, g_rangeStart, g_rangeEnd)
			}

			if g_rangeStart == 0 {
				hash = md5.New().Sum(data)
			} else {
				if region.MBI.BaseAddress <= g_rangeStart && region.MBI.BaseAddress+region.MBI.RegionSize >= g_rangeEnd {
					// single-region mode, calculcte only region hash
					hash = md5.New().Sum(data[g_rangeStart-region.MBI.BaseAddress : g_rangeEnd-region.MBI.BaseAddress])
				} else {
					// range spans multiple regions, calculate full region hash
					hash = md5.New().Sum(data)
				}
			}

			if g_uniq {
				hashArr := [16]byte{}
				copy(hashArr[:], hash)

				if _, ok := uniqHashes[hashArr]; ok {
					return false
				}
				uniqHashes[hashArr] = true
			}

			prevHash, ok := hashes[region.MBI.BaseAddress]
			if !ok || !bytes.Equal(prevHash, hash) {
				hashes[region.MBI.BaseAddress] = hash
				return true
			}

			return false
		})

		if nBytesDumped > 0 {
			nDumps++
			iDir++
			if maxDumps > 0 && nDumps >= maxDumps {
				break
			}
		}

		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

func find(args []string) {
	var pattern poker.Pattern
	pattern.FromHexString(args[0])
	for match := range openProcess().FindEach(pattern) {
		fmt.Printf("%0*x\n", poker.PtrFmtSize(), match)
	}
}

func findstr(args []string) {
	process := openProcess()

	var pattern poker.Pattern
	pattern.FromAnsiString(args[0])
	for match := range process.FindEach(pattern) {
		fmt.Printf("%0*x\n", poker.PtrFmtSize(), match)
	}
	pattern.FromUnicodeString(args[0])
	for match := range process.FindEach(pattern) {
		fmt.Printf("%0*x\n", poker.PtrFmtSize(), match)
	}
}

func findFirstEx(args []string) {
	region_type := parseHex(args[0], "region_type")
	region_prot := parseHex(args[1], "region_prot")
	var pattern poker.Pattern
	pattern.FromHexString(strings.Join(args[2:], " "))
	result := openProcess().FindFirstEx(uint32(region_type), uint32(region_prot), pattern)
	if !poker.ScriptMode || g_debug {
		if result != nil {
			poker.HexDump(result, 0)
		}
	}
}

func peek(args []string) {
	size := uintptr(0x100)
	if len(args) == 2 {
		size = uintptr(parseHex(args[1], "size"))
	}
	ea := uintptr(parseHex(args[0], "address"))
	poker.HexDump(openProcess().ReadMemory(ea, size), ea)
}

func read(args []string) {
	result := openProcess().ReadMemory(uintptr(parseHex(args[0], "ea")), uintptr(parseHex(args[1], "size")))
	if !poker.ScriptMode {
		if result != nil {
			os.Stdout.Write(result)
		}
	}
}

func patch(args []string) {
	ea := uintptr(parseHex(args[0], "ea"))
	var old_bytes poker.Pattern
	old_bytes.FromHexString(args[1])
	if old_bytes.Length() == 0 {
		panic("old_bytes.Length() == 0")
	}

	var new_bytes poker.Pattern
	new_bytes.FromHexString(args[2])
	if new_bytes.Length() == 0 {
		panic("new_bytes.Length() == 0")
	}

	maxLen := old_bytes.Length()
	if new_bytes.Length() > maxLen {
		maxLen = new_bytes.Length()
	}

	process := openProcess()
	for {
		bytes := process.ReadMemory(ea, uintptr(maxLen))
		if old_bytes.Find(bytes) == 0 {
			new_bytes.Patch(bytes, 0)
			process.WriteMemory(ea, bytes)
			break
		} else if new_bytes.Find(bytes) == 0 {
			// already patched
			break
		}
		if g_wait {
			if process.IsSuspended() {
				process.Resume()
			} else {
				time.Sleep(1 * time.Millisecond)
			}
		} else {
			break
		}
	}
}

func patch32(args []string) {
	ea := uintptr(parseHex(args[0], "ea"))
	old_value := uint32(parseHex(args[1], "old_value"))
	new_value := uint32(parseHex(args[2], "new_value"))

	process := openProcess()
	for {
		value := process.ReadUInt32(ea)
		if value == old_value {
			process.WriteUInt32(ea, new_value)
			break
		} else if value == new_value {
			// already patched
			break
		}
		if g_wait {
			if process.IsSuspended() {
				process.Resume()
			} else {
				time.Sleep(1 * time.Millisecond)
			}
		} else {
			break
		}
	}
}

// args[0]   - ea
// args[1..] - bytes to write
func poke(args []string) {
	ea := uintptr(parseHex(args[0], "ea"))
	var new_bytes poker.Pattern
	new_bytes.FromArgs(args[1:])

	process := openProcess()
	bytes := process.ReadMemory(ea, uintptr(new_bytes.Length()))
	new_bytes.Patch(bytes, 0)
	process.WriteMemory(ea, bytes)
}

func poke32(args []string) {
	ea := uintptr(parseHex(args[0], "ea"))
	value := uint32(parseHex(args[1], "value"))
	openProcess().WriteUInt32(ea, value)
}

func run(args []string) {
	g_wait = true // for patch()
	g_process = poker.StartProcess(args[0])
	g_needResume = true
}

func suspend(args []string) {
	openProcess().Suspend()
	g_needResume = false
}

func resume(args []string) {
	openProcess().Resume()
	g_needResume = false
}

func finish() {
	if g_process != nil && g_process.IsSuspended() && g_needResume {
		g_process.Resume()
	}
}

func validate(args [][]string) {
	for _, group := range args {
		if len(group) == 0 {
			panic("validate: empty group")
		}
		cmd, ok := g_commands[group[0]]
		if !ok {
			panic("validate: invalid command: " + group[0])
		}

		numArgs := len(group) - 1
		if cmd.MinArgs != -1 && numArgs < cmd.MinArgs {
			panic("validate: too few arguments for command: " + group[0])
		}
		if cmd.MaxArgs != -1 && numArgs > cmd.MaxArgs {
			panic("validate: too many arguments for command: " + group[0])
		}
	}
}

func setRange(args []string) {
	if len(args) == 1 {
		g_rangeStart = uintptr(parseHex(args[0], "start"))
		g_rangeEnd = g_rangeStart
	} else {
		g_rangeStart = uintptr(parseHex(args[0], "start"))
		g_rangeEnd = uintptr(parseHex(args[1], "end"))
	}
}

func registerCommands() {
	registerFlag("wait", 0, 0, func(args []string) { g_wait = true })
	registerFlag("sparse", 0, 0, func(args []string) { g_sparse = true })
	registerFlag("pid", 1, 1, savePid)
	registerFlag("exe", 1, 1, exe2pid)
	registerFlag("range", 1, 2, setRange)
	registerFlag("uniq", 0, 0, func(args []string) { g_uniq = true })

	registerCommand("comment", -1, -1, func(args []string) {})
	registerCommand("diffdump", 0, 2, diffdump)
	registerCommand("dump", 0, 1, dump)
	registerCommand("find", 1, 1, find)
	registerCommand("findfirstex", 3, 3, findFirstEx)
	registerCommand("findstr", 1, 1, findstr)
	registerCommand("patch", 3, 3, patch)
	registerCommand("patch32", 3, 3, patch32)
	registerCommand("peek", 1, 2, peek)
	registerCommand("poke", 2, -1, poke)
	registerCommand("poke32", 2, 2, poke32)
	registerCommand("ps", 0, 0, ps)
	registerCommand("read", 2, 2, read)
	registerCommand("regions", 0, 0, regions)
	registerCommand("resume", 0, 0, resume)
	registerCommand("run", 1, 1, run)
	registerCommand("suspend", 0, 0, suspend)
}
