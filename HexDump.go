package poker

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
            var c byte = 0
            if i+j < len(buffer) {
                c = buffer[i+j]
            }

            if c >= 32 && c <= 126 {
				fmt.Printf("%c", c)
            } else if c == 0 {
                fmt.Printf(" ")
			} else {
                fmt.Printf(".")
            }
		}

		fmt.Println("|")
	}
}
