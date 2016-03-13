package main

import (
	"io/ioutil"
	"encoding/base64"
	"cryptopals/utils"
	"fmt"
)

var data, key, nonce, encrypted []byte

func init() {
	file_contents, err := ioutil.ReadFile("./25.txt")

	if err != nil {
		panic("Starting in wrong directory?")
	}

	data, _ = base64.StdEncoding.DecodeString(string(file_contents))

	data = utils.AesEcbDecrypt(data, []byte("YELLOW SUBMARINE"))

	key = utils.GenKey(16)
	nonce = utils.GenKey(8)

	encrypted = make([]byte, len(data))

	utils.AesCtr(encrypted, data, key, nonce)
}

func edit(ciphertext, newtext, key, nonce []byte, offset int) {
	// This is probably simpler than advancing the keystream to
	// the right point and splicing the new results into the ciphertext.

	utils.AesCtr(ciphertext, ciphertext, key, nonce)
	b := ciphertext[:0]
	b = append(ciphertext[:offset], newtext...)
	b = append(b, ciphertext[offset + len(newtext):]...)
	utils.AesCtr(ciphertext, ciphertext, key, nonce)
}

func edit_no_key(ciphertext, newtext []byte, offset int) {
	edit(ciphertext, newtext, key, nonce, offset)
}

func main() {
	null := make([]byte, len(encrypted))
	orig := make([]byte, len(encrypted))
	copy(orig, encrypted)

	// fmt.Printf("%q\n", null)
	edit_no_key(encrypted, null, 0)

	// "encrypted" is now the keystream


	result := make([]byte, len(encrypted))

	e := utils.FixedXORBuffer(result, orig, encrypted)

	if e != nil {
		panic("Error XORing buffers!")
	}

	fmt.Printf("%q\n", result)
}