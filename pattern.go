package dumper

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

func (p *Pattern) FromHexString(s string) {
    p.data = []int{}
    for _, c := range strings.Fields(s) {
        if c == "?" || c == "??" {
            p.data = append(p.data, -1)
        } else {
            x, err := strconv.ParseUint(string(c), 16, 8)
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
