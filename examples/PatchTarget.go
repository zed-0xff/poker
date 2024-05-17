package main

import (
    "fmt"

    "github.com/zed-0xff/dumper"
    "golang.org/x/sys/windows"
)

func main() {
    process := dumper.CreateProcess(
        "Target.exe",
        []string{},
        dumper.WithFlags(windows.CREATE_SUSPENDED),
    )

    defer process.Close()
    //defer process.Resume()

    addr := uintptr(0x0c9d0)

    for _, region := range process.Regions() {
        if region.IsCommitted() && region.IsImage() && region.MBI.RegionSize > (addr+4) {
            region.Show()
            value := process.ReadUInt32(addr + region.MBI.BaseAddress)
            fmt.Printf("[d] Value at %x: %x\n", addr, value)
        }
    }

//    if( value != 12345 ) {
//        panic("Value is not 12345")
//    }
//
//    process.WriteUInt32(addr, 31337)
}
