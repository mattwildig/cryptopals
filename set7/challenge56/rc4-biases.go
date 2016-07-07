package main

import (
	"crypto/rc4"
	"fmt"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

const secret = 'A'

func rc4Oracle(prefix []byte) []byte {
	cipher, err := rc4.NewCipher(utils.GenKey(16))
	if err != nil {
		panic("Error creating cipher")
	}

	dest := make([]byte, len(prefix) + 1)
	plain := append(prefix, secret)

	cipher.XORKeyStream(dest, plain)

	return dest
}

func main() {
	text.PrintGreen("Starting")
	prefix := make([]byte, 15)

	var results [256]int64

	for i := 0; i < 10000000; i++ {
		if i % 1000 == 0 {
			fmt.Printf("\r%d\033[K", i)
		}
		c := rc4Oracle(prefix)
		results[c[15]]++
	}

	var max int64 = 0
	var maxIndex int = -1
	for i, v := range(results) {
		if v > max {
			max = v
			maxIndex = i
		}
	}

	// Bias at position 16 is for byte 240
	decodedChar := byte(maxIndex) ^ byte(240)
	fmt.Printf("Decoded char: %s\n", string(decodedChar))

	if decodedChar == secret {
		text.PrintGreen("Correctly decoded secret")
	} else {
		text.PrintRed("Incorrectly decoded secret")
	}
}