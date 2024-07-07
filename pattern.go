package poker

import (
	"fmt"
	"strconv"
	"strings"
)

type Pattern struct {
	data []int // -1 means wildcard
}

func (p Pattern) Length() int {
	return len(p.data)
}

func (p Pattern) String() string {
	s := ""
	for _, c := range p.data {
		if c == -1 {
			s += "?? "
		} else {
			s += fmt.Sprintf("%02X ", c)
		}
	}
	return strings.TrimSpace(s)
}

func (p Pattern) Find(buffer []byte) int {
	for i := 0; i < len(buffer); i++ {
		if p.data[0] == -1 || int((buffer)[i]) == p.data[0] {
			found := true
			for j := 1; j < len(p.data); j++ {
				if i+j >= len(buffer) || (p.data[j] != -1 && int((buffer)[i+j]) != p.data[j]) {
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

func (p Pattern) Patch(buffer []byte, offset int) {
	for i := 0; i < len(p.data); i++ {
		if p.data[i] != -1 {
			buffer[offset+i] = byte(p.data[i])
		}
	}
}

func (p *Pattern) FromArgs(args []string) {
	s := ""
	for i, arg := range args {
		switch len(arg) {
		case 1:
			if arg == "?" {
				s += "??"
			} else {
				s += "0" + arg
			}

		case 2:
			s += arg

		default:
			panic(fmt.Sprintf("Pattern::FromArgs: invalid argument %d: \"%s\"", i, arg))
		}
	}
	p.FromHexString(s)
}

func (p *Pattern) FromHexString(s string) {
	s = strings.ReplaceAll(s, " ", "")
//	if len(s)%2 != 0 {
//		panic("Pattern::FromHexString: odd length")
//	}
	if len(s) == 0 {
		panic("Pattern::FromHexString: empty string")
	}

	p.data = []int{}
	for i := 0; i < len(s); i+=2 {
        if s[i] == '{' {
            // skip N bytes
            j := strings.Index(s[i:], "}")
            if j == -1 {
                panic("Pattern::FromHexString: missing '}'")
            }
            nskip, err := strconv.ParseUint(s[i+1:i+j], 16, 8)
            if err != nil {
                panic(err)
            }
            for k := 0; k < int(nskip); k++ {
                p.data = append(p.data, -1)
            }
            i += j - 1
            continue
        }

		b := s[i : i+2]
		if b == "??" {
			p.data = append(p.data, -1)
		} else {
			x, err := strconv.ParseUint(b, 16, 8)
			if err != nil {
				panic(err)
			}
			p.data = append(p.data, int(x))
		}
	}
}

func (p *Pattern) FromAnsiString(s string) {
	p.data = []int{}
	for _, c := range s {
		p.data = append(p.data, int(c))
	}
}

func (p *Pattern) FromUnicodeString(s string) {
	p.data = []int{}
	for _, c := range s {
		p.data = append(p.data, int(c))
		p.data = append(p.data, 0)
	}
}

func ParsePattern(src string) Pattern {
	p := Pattern{}
	p.FromHexString(src)
	return p
}
