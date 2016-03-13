package main

import (
	"fmt"
	"cryptopals/utils"
	"math/rand"
	"bytes"
)

func main() {
	fmt.Println("Starting")

	input := make([]byte, 50 + rand.Intn(100))

	for i := 0; i < len(input); i++ {
		input[i] = byte(rand.Intn(256))
	}

	known := []byte("aaaaaaaaaa")
	input = append(input, known...)

	max16bitPlus1 := int(^uint16(0)) + 1
	key := uint16(rand.Intn(max16bitPlus1))

	encrypted := make([]byte, len(input))
	utils.MersenneEncrypt(encrypted, input, key)

	guessed_seed := uint32(max16bitPlus1)

	decrypted := make([]byte, len(input))
	for i := uint32(0); i < uint32(max16bitPlus1); i++ {
		utils.MersenneEncrypt(decrypted, encrypted, uint16(i))
		if bytes.Contains(decrypted, known) {
			guessed_seed = i
			break
		}
	}

	if guessed_seed == uint32(max16bitPlus1) {
		fmt.Printf("Unable to find seed, was: %d\n", key)
	} else {
		fmt.Printf("Guessed key: %d, Actual: %d\n", guessed_seed, key)
	}

}