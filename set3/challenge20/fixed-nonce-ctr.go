package main

import (
	"io/ioutil"
	"bytes"
	"cryptopals/utils"
	"fmt"
	"encoding/base64"
)

var key = []byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}//utils.GenKey(16)
var nonce = make([]byte, 8)

func main() {
	data, err := ioutil.ReadFile("./20.txt")
	if err != nil {
		fmt.Println("Can’t read file, you’re probably in the wrong directory!")
		return
	}

	plains := bytes.Split(data, []byte("\n"))
	ciphers := make([][]byte, 0)

	for _, p64 := range plains {
		if len(p64) == 0 {
			continue
		}
		p, _ := base64.StdEncoding.DecodeString(string(p64))

		utils.AesCtr(p, p, key, nonce)

		ciphers = append(ciphers, p)
		// fmt.Printf("%q\n", p)
	}


	results := utils.DecryptFixedNonceCtr(ciphers)

	for _, r := range results {
		fmt.Println(string(r))
	}
}