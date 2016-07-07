package main

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

const DEFAULT_LOOP_COUNT = 10000000
var loopCount int
var coolingDelay int
var help = false

var encodedSecret = "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"
var secret []byte

func init() {
	flag.IntVar(&coolingDelay, "c", 0, "Delay (in seconds) to wait between characters")
	flag.IntVar(&loopCount, "l", DEFAULT_LOOP_COUNT,
		"Number of encryptions to obtain for each character")
	flag.BoolVar(&help, "h", false, "Show usage and exit")

	var err error
	secret, err = base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		text.PrintRed("Error base64 decoding secret")
		os.Exit(1)
	}
}

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
			fmt.Print("\033[34mX\033[m")
		} else if c < 32 || c > 126 {
			fmt.Print("\033[31m?\033[m")
		} else {
			fmt.Printf("\033[32m%s\033[m", string(c))
		}
	}
	fmt.Print("\033[K")
}

func main() {
	flag.Parse()
	if help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	text.PrintGreen("Starting")

	prefix := make([]byte, 16)
	result := make([]byte, len(secret))

	printResult(result)
	fmt.Println()

	for position := 0; position < 16; position++ {
		var results16, results32 [256]int64

		prefix = prefix[1:]

		for i := 0; i < loopCount; i++ {
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

		if coolingDelay > 0 && position < 15 {
			fmt.Print("Cooling...")
			time.Sleep(time.Duration(coolingDelay) * time.Second)
			fmt.Print("\r\033[K")
		}

	}
	if  bytes.Equal(result, secret) {
		text.PrintGreen("Successfully decoded secret")
	} else {
		text.PrintRed("Incorrectly decoded secret")
	}
	fmt.Print("\033[K")
}
