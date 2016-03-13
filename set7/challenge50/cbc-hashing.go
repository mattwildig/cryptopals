package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	// "io/ioutil"

	"cryptopals/utils"
)

var (
	iv = make([]byte, 16)
	key = []byte("YELLOW SUBMARINE")
)

func cbcHash(m []byte) []byte {
	data := utils.AesCbcEncrypt(utils.PKCS7(m, 16), key, iv)
	hash := data[len(data) - 16:]

	return hash
}

func main() {
	orig := []byte("alert('MZA who was that?');\n")
	hash := cbcHash(orig)

	fmt.Println(hex.EncodeToString(hash))

	// padded := utils.PKCS7(orig, 16)
	// encrypted := utils.AesCbcEncrypt(padded, key, iv)

	injected := []byte("alert('Ayo, the Wu is back!');//") // 32 bytes, 2 blocks
	encrypted := utils.AesCbcEncrypt(injected, key, iv)

	utils.FixedXORBuffer(orig[:16], orig[:16], encrypted[len(encrypted)-16:])
	message := append(injected, orig...)

	new_hash := cbcHash(message)
	fmt.Println("Forged message:")
	fmt.Printf("%q\n", message)

	fmt.Println(hex.EncodeToString(new_hash))
	fmt.Printf("Hashes are equal: %v\n", bytes.Equal(hash, new_hash))

	// write the file, for testing it's valid js (uncomment import too)
	//ioutil.WriteFile("test.js", message, 0770)

}