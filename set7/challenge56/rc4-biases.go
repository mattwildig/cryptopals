package main

import (
	"crypto/rc4"
	"fmt"
	"os"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

func rc4Oracle(prefix []byte) []byte {
	cipher, err := rc4.NewCipher(utils.GenKey(16))
	if err != nil {
		panic("Error creating cipher")
	}

	dest := make([]byte, len(prefix) + 1)
	plain := append(prefix, 'A')

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
	fmt.Println("\rWriting file\033[K")

	file, file_error := os.Create("rc4_counts.txt")
	if file_error != nil {
		panic("Error! An error has happened opening the file!")
	}

	for i, v := range(results) {
		fmt.Fprintf(file, "%d  %d\n", i, v)
	}

	text.PrintGreen("Done")
}