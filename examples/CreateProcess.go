package main

import (
    "github.com/zed-0xff/dumper"
)

func main() {
    process := dumper.CreateProcess("C:\\Windows\\System32\\calc.exe", []string{})
    defer process.Close()
}
