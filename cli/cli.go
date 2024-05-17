package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

    "golang.org/x/sys/windows"
	"github.com/zed-0xff/dumper"
)

var g_debug bool = false

func usage() {
	fmt.Print(
		"Universal memory patcher/dumper v", dumper.Version, " by zed_0xff\n",
		"Usage:\n",
		"    dumper ps\n",
		"    dumper <pid_or_exename> list\n",
		"    dumper <pid_or_exename> dump <addr>\n",
		"    dumper <pid_or_exename> dump all\n",
		"    dumper <pid_or_exename> find <bytes>\n",
		"    dumper <pid_or_exename> show <addr> [size]\n",
		"    dumper <pid_or_exename> read <addr> <size>\n",
		"    dumper <pid_or_exename> write_uint32 <addr> <value>\n",
	)
}

func pop(args *[]string) string {
	arg := (*args)[0]
	*args = (*args)[1:]
	return arg
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

func run(args []string) []byte {
	if dumper.Verbosity > 0 {
		fmt.Println("[d] run(", args, ")")
	}

	if len(args) == 0 {
		usage()
		return nil
	}

	if args[0] == "ps" {
		dumper.ShowProcesses()
		return nil
	}

	arg := pop(&args)
	pid := dumper.ParsePidOrExe(arg)
	if pid == 0 {
		fmt.Println("Process not found:", arg)
		os.Exit(1)
	}

    process := dumper.OpenProcess(pid, windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ);
    defer process.Close()

	if len(args) == 0 {
		process.ShowRegions()
		return nil
	}

	arg = strings.ToLower(pop(&args))

	switch arg {
	case "list":
		if len(args) != 0 {
			usage()
			os.Exit(1)
		}
		process.ShowRegions()
	case "dump":
		if len(args) == 0 {
			usage()
			os.Exit(1)
		}
		if args[0] == "all" {
			process.DumpAll()
		} else {
			process.DumpRegion(uintptr(parseHex(args[0], "address")))
		}
	case "find":
		if len(args) != 1 {
			usage()
			os.Exit(1)
		}
		pattern := dumper.ParsePattern(args[0])
		for match := range process.FindEach(pattern) {
			fmt.Printf("%x\n", match)
		}
	case "findfirstex":
		if len(args) < 3 {
			usage()
			os.Exit(1)
		}

		region_type := parseHex(args[0], "region_type")
		region_prot := parseHex(args[1], "region_prot")
		pattern := dumper.ParsePattern(strings.Join(args[2:], " "))
		result := process.FindFirstEx(uint32(region_type), uint32(region_prot), pattern)
		if !dumper.ScriptMode || g_debug {
			if result != nil {
				dumper.HexDump(result, 0)
			}
		}
		return nil
	case "show":
		if len(args) > 2 {
			usage()
			os.Exit(1)
		}
		size := uintptr(0x100)
		if len(args) == 2 {
			size = uintptr(parseHex(args[1], "size"))
		}
		ea := uintptr(parseHex(args[0], "address"))
        dumper.HexDump(process.ReadMemory(ea, size), ea)

	case "read":
		if len(args) != 2 {
			usage()
			os.Exit(1)
		}

		result := process.ReadMemory(uintptr(parseHex(args[0], "ea")), uintptr(parseHex(args[1], "size")))
		if !dumper.ScriptMode {
			if result != nil {
				os.Stdout.Write(result)
			}
		}
		return result
	case "write_uint32":
		if len(args) != 2 {
			usage()
			os.Exit(1)
		}
		ea := uintptr(parseHex(args[0], "ea"))
		value := uint32(parseHex(args[1], "value"))
		process.WriteUInt32(ea, value)
	default:
		fmt.Println("[?] Invalid command:", arg)
		usage()
		os.Exit(1)
	}

	return nil
}

func main() {
	args := []string{}

	for _, arg := range os.Args[1:] {
		arg = strings.ToLower(arg)
		if arg == "help" || arg == "-h" || arg == "--help" {
			usage()
			return
		}
		if arg == "--debug" {
			g_debug = true
			dumper.Verbosity++
			continue
		}
		if arg == "--noscript" || arg == "--no-script" {
			dumper.ScriptMode = false
			continue
		}
		if arg == "-s" || arg == "-q" {
			dumper.Verbosity--
			continue
		}
		if arg == "-v" || arg == "--verbose" {
			dumper.Verbosity++
			continue
		}
		args = append(args, arg)
	}

	run(args)
}
