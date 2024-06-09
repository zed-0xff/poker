package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
    "time"

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
		"    dumper <pid_or_exename> dump <addr1>..<addr2> [--sparse]\n",
		"    dumper <pid_or_exename> dump all [--sparse]\n",
		"    dumper <pid_or_exename> find <bytes>\n",
		"    dumper <pid_or_exename> findstr \"string\"\n",
		"    dumper <pid_or_exename> show <addr> [size]\n",
		"    dumper <pid_or_exename> read <addr> <size>\n",
		"    dumper <pid_or_exename> patch   <addr> <old_bytes> <new_bytes>\n",
		"    dumper <pid_or_exename> patch32 <addr> <old_value> <new_value>\n",
		"    dumper <pid_or_exename> write32 <addr> <value>\n",
        "\n",
        "flags:\n",
        "    --wait - wait for specified process, if it's not running\n",
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

    // remove '_' separators, if any
    s = strings.ReplaceAll(s, "_", "")

	x, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		fmt.Printf("[?] Invalid %s: %s\n", title, s)
		os.Exit(1)
	}
	return x
}

func run(args []string) []byte {
    var pid uint32

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

    flag_wait := false
    // if args contains "--wait" at any position then set flag_wait to true, and remove "--wait" from args
    for i := 0; i < len(args); i++ {
        if args[i] == "--wait" {
            flag_wait = true
            args = append(args[:i], args[i+1:]...)
            break
        }
    }

	arg := pop(&args)
    wait_message_shown := false

    for {
        pid = dumper.ParsePidOrExe(arg)
        if pid == 0 {
            if flag_wait {
                if !wait_message_shown {
                    wait_message_shown = true
                    fmt.Println("[.] Waiting for process:", arg)
                }
                time.Sleep(1 * time.Millisecond)
                continue
            } else {
                fmt.Println("Process not found:", arg)
                os.Exit(1)
            }
        }
        break
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
        
        // if args contains "--sparse" at any position then set sparse to true, and remove "--sparse" from args
        sparse := false
        for i := 0; i < len(args); i++ {
            if args[i] == "--sparse" {
                sparse = true
                args = append(args[:i], args[i+1:]...)
                break
            }
        }

		if args[0] == "all" {
            process.DumpRange(uintptr(0), ^uintptr(0), sparse)

        } else if strings.Contains(args[0], "..") {
            addresses := strings.Split(args[0], "..")
            start := uintptr(parseHex(addresses[0], "start"))
            end := uintptr(parseHex(addresses[1], "end"))

            process.DumpRange(start, end, sparse)
		} else {
			process.DumpRegion(uintptr(parseHex(args[0], "address")))
		}

	case "find":
		if len(args) != 1 {
			usage()
			os.Exit(1)
		}
        var pattern dumper.Pattern
        pattern.FromHexString(args[0])
		for match := range process.FindEach(pattern) {
			fmt.Printf("%0*x\n", dumper.PtrFmtSize(), match)
		}

	case "findstr":
		if len(args) != 1 {
			usage()
			os.Exit(1)
		}
		var pattern dumper.Pattern
        pattern.FromAnsiString(args[0])
		for match := range process.FindEach(pattern) {
			fmt.Printf("%0*x\n", dumper.PtrFmtSize(), match)
		}
        pattern.FromUnicodeString(args[0])
		for match := range process.FindEach(pattern) {
			fmt.Printf("%0*x\n", dumper.PtrFmtSize(), match)
		}

	case "findfirstex":
		if len(args) < 3 {
			usage()
			os.Exit(1)
		}

		region_type := parseHex(args[0], "region_type")
		region_prot := parseHex(args[1], "region_prot")
        var pattern dumper.Pattern
        pattern.FromHexString(strings.Join(args[2:], " "))
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

    case "patch":
		if len(args) != 3 {
			usage()
			os.Exit(1)
		}
		ea := uintptr(parseHex(args[0], "ea"))
        var old_bytes dumper.Pattern
        old_bytes.FromHexString(args[1])
        if old_bytes.Length() == 0 {
            panic("old_bytes.Length() == 0")
        }

        var new_bytes dumper.Pattern
        new_bytes.FromHexString(args[2])
        if new_bytes.Length() == 0 {
            panic("new_bytes.Length() == 0")
        }

        maxLen := old_bytes.Length()
        if new_bytes.Length() > maxLen {
            maxLen = new_bytes.Length()
        }

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
            if flag_wait {
                time.Sleep(1 * time.Millisecond)
            } else {
                break
            }
        }

	case "patch32":
		if len(args) != 3 {
			usage()
			os.Exit(1)
		}
		ea := uintptr(parseHex(args[0], "ea"))
		old_value := uint32(parseHex(args[1], "old_value"))
		new_value := uint32(parseHex(args[2], "new_value"))
        for {
            value := process.ReadUInt32(ea)
            if value == old_value {
                process.WriteUInt32(ea, new_value)
                break
            } else if value == new_value {
                // already patched
                break
            }
            if flag_wait {
                time.Sleep(1 * time.Millisecond)
            } else {
                break
            }
        }

	case "write32":
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
