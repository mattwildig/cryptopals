package main

import (
	"bytes"
	"crypto/rc4"
	"fmt"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

var secret = []byte("Stick the kettle on and find me ") // Max 32 bytes

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

func printResult(result []byte) {
	for _, c := range(result) {
		if c == 0 {
			fmt.Print("\033[31mX\033[m")
		} else {
			fmt.Printf("\033[32m%s\033[m", string(c))
		}
	}
	fmt.Print("\033[K")
}

func main() {
	text.PrintGreen("Starting")

	prefix := make([]byte, 16)
	result := make([]byte, len(secret))

	printResult(result)
	fmt.Println()

	for position := 0; position < 16; position++ {
		var results16, results32 [256]int64

		prefix = prefix[1:]

		for i := 0; i < 10000000; i++ {
			if i % 1000 == 0 {
				fmt.Printf("\r%d\033[K", i)
			}
			c := rc4Oracle(prefix)
			results16[c[15]]++
			if len(c) >= 32 {
				results32[c[31]]++
			}
		}
		fmt.Print("\r\033[K")

		// Bias at position 16 is for byte 240
		decodedChar16 := byte(maxIndex(results16)) ^ byte(240)
		result[position] = decodedChar16

		if len(prefix) + len(secret) >=32 {
			// Bias at position 16 is for byte 224
			decodedChar32 := byte(maxIndex(results32)) ^ byte(224)
			result[position + 16] = decodedChar32
		}
		fmt.Print("\033[1F") // move up 1 line
		printResult(result)
		fmt.Print("\033[1E") // move back down

	}
	if  bytes.Equal(result, secret) {
		text.PrintGreen("Successfully decoded secret")
	} else {
		text.PrintRed("Incorrectly decoded secret")
	}
	fmt.Print("\033[K")
}
