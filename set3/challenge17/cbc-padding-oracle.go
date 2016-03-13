package main

import (
	"math/rand"
	"encoding/base64"
	"fmt"
	"cryptopals/utils"
	"time"
)

var secretKey []byte

func init() {
	rand.Seed(int64(time.Now().Nanosecond()))
	secretKey = utils.GenKey(16)
}

var strings = [...]string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func getData() []byte {
	chosen := strings[rand.Intn(len(strings))]
	// chosen := strings[3]

	// fmt.Printf("Using: %s\n", chosen)

	target, _ := base64.StdEncoding.DecodeString(chosen)
	target = utils.PKCS7(target, 16)

	iv := utils.GenKey(16)

	encrpted := utils.AesCbcEncrypt(target, secretKey, iv)

	return append(iv, encrpted...)
}

func DecryptAndCheckPadding(encrypted []byte) bool {
	decrypted := utils.AesCbcDecrypt(encrypted[16:], secretKey, encrypted[:16])

	_, invalid := utils.CheckAndStripPKCS7(decrypted)

	if invalid != nil {
		return false
	}

	return true
}

func main() {
	data := getData()
	decrypted := make([]byte, len(data) - 16)
	decryptedBuffer := decrypted[:]

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("%q\n", decrypted)
			fmt.Println("PANICKED!")
			return
		}
	}()

	for len(data) >= 32 {
		decryptBlock(data[:32], decryptedBuffer[:16])
		data = data[16:]
		decryptedBuffer = decryptedBuffer[16:]
	}

	fmt.Printf("%q\n", decrypted)
}

func decryptBlock(input, dest []byte) {
	first_block := make([]byte, 16)
	copy(first_block, input[:16])
	second_block := make([]byte, 16)
	copy(second_block, input[16:])

	tampered_block := make([]byte, 16)
	intermediate := make([]byte, 16)

	found := false

	for position := 15; position >=0; position-- {
		padding := 16 - position
		for attempt := 0; attempt < 256; attempt++ {
			tampered_block[position] = byte(attempt)

			thisCheck := append(tampered_block, second_block...)
			// fmt.Println(thisCheck)
			if DecryptAndCheckPadding(thisCheck) {
				// fmt.Printf("found for %d\n", attempt)
				intermediate[position] = byte(padding) ^ byte(attempt)
				dest[position] = first_block[position] ^ intermediate[position]

				// fmt.Printf("s is %d, next target is: %d\n", position, byte(17 - position))
				for s := position; s < 16; s++ {
					tampered_block[s] = byte(padding + 1) ^ intermediate[s]
				}

				// fmt.Println(tampered_block)
				// fmt.Println(dest)
				found = true
				break
			}
		}
		if ! found {
			fmt.Printf("%q\n", dest)
			panic("decrypt not found")
		}
		found = false
	}
}


