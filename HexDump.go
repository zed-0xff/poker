package dumper

import (
    "fmt"
)

// prints hexdump, 16 bytes per line, with ascii chars on the right
func HexDump(buffer []byte, ea uintptr) {
	for i := 0; i < len(buffer); i += 16 {
		fmt.Printf("%19X:", uintptr(i)+ea)
		for j := 0; j < 16; j++ {
			if j == 8 {
				fmt.Printf(" ")
			}
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
