package main

import (
	"cryptopals/utils"
	"strings"
	"fmt"
)

var prefix = "comment1=cooking%20MCs;userdata="
var suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

var secretKey = utils.GenKey(16)
// var iv = utils.GenKey(16)

func encrypt(input string) []byte {
	input = strings.NewReplacer(";", "%3B", "=", "%3D").Replace(input)

	input = fmt.Sprintf("%s%s%s", prefix, input, suffix)

	// fmt.Printf("%q\n", input)

	inputBytes := utils.PKCS7([]byte(input), 16)

	return utils.AesCbcEncrypt(inputBytes, secretKey, secretKey)

}

func checkASCII(input []byte) bool {
	for _, c := range input {
		if c > 127 {
			return false
		}
	}
	return true
}

type InvalidData struct {
	decrypted []byte
}

func (InvalidData) Error() string {
	return "Invalid decryption"
}

func decryptAndCheckASCII(input []byte) *InvalidData {
	decrypted := utils.AesCbcDecrypt(input, secretKey, secretKey)

	if checkASCII(decrypted) {
		return nil
	} else {
		return &InvalidData{decrypted}
	}
}

func main() {

	encrypted := encrypt("YELLOW SUBMARINEYELLOW SUBMARINE")
 
	r := decryptAndCheckASCII(append(encrypted[0:16], append(make([]byte, 16), encrypted[0:16]...)...))

	key, _ := utils.FixedXOR(r.decrypted[0:16], r.decrypted[32:48])

	fmt.Printf("extracted key: %q\n", key)
	fmt.Printf("   actual key: %q\n", secretKey)
}


