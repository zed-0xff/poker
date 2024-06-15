package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/zed-0xff/poker"
)

var g_debug bool = false

func usage() {
	fmt.Print(
		"Universal memory patcher/poker v", poker.Version, " by zed_0xff\n",
		"commands:\n",
	)

	maxLen := 0
	var names []string
	for name := range g_commands {
		names = append(names, name)
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		cmd := g_commands[name]

		if cmd.MinArgs == 0 {
			fmt.Printf("    --%s\n", name)
		} else if cmd.MinArgs == cmd.MaxArgs {
			fmt.Printf("    --%*s [%d]\n", -maxLen, name, cmd.MinArgs)
		} else {
			fmt.Printf("    --%*s [%d..%d]\n", -maxLen, name, cmd.MinArgs, cmd.MaxArgs)
		}
	}

	fmt.Print(
		"\nflags:\n",
		"    --wait - wait for specified process if it's not running\n",
	)
}

func runArgs(args [][]string) {
	if poker.Verbosity > 0 {
		fmt.Println("[d] runArgs(", args, ")")
	}

	for _, cargs := range args {
		cmd_name := cargs[0]
		cmd, _ := g_commands[cmd_name]
		cmd.Func(cargs[1:])
	}
}

// parseArgs takes a slice of strings and parses it into a slice of slices based on flags starting with "--"
func parseArgs(args []string) [][]string {
	if len(args) == 0 || !strings.HasPrefix(args[0], "--") {
		panic("parseArgs: first argument must start with '--'")
	}

	var result [][]string
	var currentGroup []string

	for _, arg := range args {
		// Check if the argument is a flag
		if strings.HasPrefix(arg, "--") {
			if currentGroup != nil {
				// If a current group exists, add it to the result
				result = append(result, currentGroup)
			}
			// Start a new group
			currentGroup = []string{arg[2:]}
		} else {
			// Add the argument to the current group
			currentGroup = append(currentGroup, arg)
		}
	}

	// Add the last group if it's not empty
	if currentGroup != nil {
		result = append(result, currentGroup)
	}

	return result
}

func main() {
	registerCommands()

	args := []string{}
	for _, arg := range os.Args[1:] {
		arg = strings.ToLower(arg)
		if arg == "help" || arg == "-h" || arg == "--help" {
			usage()
			return
		}
		if arg == "--debug" {
			g_debug = true
			poker.Verbosity++
			continue
		}
		if arg == "--noscript" || arg == "--no-script" {
			poker.ScriptMode = false
			continue
		}
		if arg == "-q" {
			poker.Verbosity--
			continue
		}
		if arg == "-v" || arg == "--verbose" {
			poker.Verbosity++
			continue
		}
		args = append(args, arg)
	}

	if len(args) == 0 {
		usage()
		return
	}

	pargs := parseArgs(args)
	validate(pargs)
	runArgs(pargs)
	finish()
}
