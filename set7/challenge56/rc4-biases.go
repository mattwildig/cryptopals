package main

import (
	"crypto/rc4"
	"fmt"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

var secret = []byte("Stick the kettle on and find me a cup")

func rc4Oracle(prefix []byte) []byte {
	cipher, err := rc4.NewCipher(utils.GenKey(16))
	if err != nil {
		panic("Error creating cipher")
	}

	dest := make([]byte, len(prefix) + len(secret))
	plain := append(prefix, secret...)

	cipher.XORKeyStream(dest, plain)

	return dest
}

func maxIndex(results [256]int64) int {
	var max int64 = 0
	var maxIndex int = -1
	for i, v := range(results) {
		if v > max {
			max = v
			maxIndex = i
		}
	}

	return maxIndex
}

func main() {
	text.PrintGreen("Starting")
	prefix := make([]byte, 15)

	var results16, results32 [256]int64

	for i := 0; i < 10000000; i++ {
		if i % 1000 == 0 {
			fmt.Printf("\r%d\033[K", i)
		}
		c := rc4Oracle(prefix)
		results16[c[15]]++
		results32[c[31]]++
	}
	fmt.Print("\r\033[K")

	// Bias at position 16 is for byte 240
	decodedChar16 := byte(maxIndex(results16)) ^ byte(240)
	fmt.Printf("Decoded char at pos 0: %s\n", string(decodedChar16))

	// Bias at position 16 is for byte 224
	decodedChar32 := byte(maxIndex(results32)) ^ byte(224)
	fmt.Printf("Decoded char at pos 16: %s\n", string(decodedChar32))

	if decodedChar16 == secret[0] && decodedChar32 == secret[16] {
		text.PrintGreen("Correctly decoded secret")
	} else {
		text.PrintRed("Incorrectly decoded secret")
	}
}