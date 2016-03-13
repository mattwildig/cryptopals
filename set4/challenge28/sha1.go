package main

import (
	"fmt"
	"cryptopals/utils"
	"encoding/hex"
	"os"
	"io/ioutil"
	"flag"
)

var s bool

func init() {
	flag.BoolVar(&s, "s", false, "")
}

func main() {
	flag.Parse()

	if s {
		fmt.Println(hex.EncodeToString(utils.SHA1Sign([]byte(flag.Arg(0)), []byte(flag.Arg(1)))))
	} else {
		input, e := ioutil.ReadAll(os.Stdin)

		if e != nil {
			panic("Error! An error has happened!")
		}
		fmt.Println(hex.EncodeToString(utils.SHA1(input)))
	}
}
