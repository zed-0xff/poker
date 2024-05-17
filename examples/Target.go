package main

import (
    "fmt"
    "time"

    "golang.org/x/sys/windows"
)

func main() {
    secretValue := 12345

    dll, err := windows.LoadLibrary("kernel32.dll")
    if err != nil {
        panic(err)
    }
    defer windows.FreeLibrary(dll)
    fmt.Printf("[d] kernel32 = %x\n", dll)

    addr, err := windows.GetProcAddress(dll, "GetSystemTimeAsFileTime")
    if err != nil {
        panic(err)
    }
    fmt.Printf("[d] func     = %x\n", addr)

    time.Sleep(1 * time.Second)
    fmt.Println("Current time:", time.Now(), "Secret value:", secretValue)
}
