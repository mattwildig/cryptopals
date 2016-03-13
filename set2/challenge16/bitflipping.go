package main

import (
	"cryptopals/utils"
	"strings"
	"fmt"
)

var prefix = "comment1=cooking%20MCs;userdata="
var suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

var secretKey = utils.GenKey(16)
var iv = utils.GenKey(16)

func encrypt(input string) []byte {
	input = strings.NewReplacer(";", "%3B", "=", "%3D").Replace(input)

	input = fmt.Sprintf("%s%s%s", prefix, input, suffix)

	// fmt.Printf("%q\n", input)

	inputBytes := utils.PKCS7([]byte(input), 16)

	return utils.AesCbcEncrypt(inputBytes, secretKey, iv)

}

func isAdmin(input string) bool {
	pairs := strings.Split(input, ";")
	for _, pair := range pairs {
		if strings.Contains(pair, "=") {
			s := strings.Split(pair, "=")
			if s[0] == "admin" && s[1] == "true" {
				return true
			}
		}
	}
	return false
}

func decryptAndCheck(input []byte) {
	decrypted := utils.AesCbcDecrypt(input, secretKey, iv)

	// fmt.Printf("%q\n", decrypted)

	if isAdmin(string(decrypted)) {
		fmt.Println("Success: Is Admin")
	} else {
		fmt.Println("Not Admin")
	}
}

func main() {

	//             prefix                         our data                   suffix
	// |-------------------------------| |--------------------------||-------------->
	//                                   |     |
	//                                   V     V
	// comment1=cooking %20MCs;userdata= YELLOW SUBMARINE 9admin9true;comm ent2=%20like%20a %20pound%20of%20 bacon
	// 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef

	encrypted := encrypt("YELLOW SUBMARINE9admin9true")

	encrypted[32] = encrypted[32] ^ 2 // 0011 1001 (9) ^ 0000 0010 (2) = 0011 1011 (;)
	encrypted[38] = encrypted[38] ^ 4 // 0011 1001 (9) ^ 0000 0100 (4) = 0011 1101 (=)


	decryptAndCheck(encrypted)
}


