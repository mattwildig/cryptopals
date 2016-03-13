package text

import (
	"fmt"
)

func PrintGreen(m string) {
	s := fmt.Sprintf("\x1b[32m%s\x1b[m", m)
	fmt.Println(s)
}

func PrintRed(m string) {
	s := fmt.Sprintf("\x1b[31m%s\x1b[m", m)
	fmt.Println(s)
}
