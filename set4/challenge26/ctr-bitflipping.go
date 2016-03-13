package main

import (
	"cryptopals/utils"
	"strings"
	"fmt"
)

var prefix = "comment1=cooking%20MCs;userdata="
var suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

var secretKey = utils.GenKey(16)
var nonce = utils.GenKey(8)

func encrypt(input string) []byte {
	input = strings.NewReplacer(";", "%3B", "=", "%3D").Replace(input)

	input = fmt.Sprintf("%s%s%s", prefix, input, suffix)

	result := make([]byte, len(input))

	utils.AesCtr(result, []byte(input), secretKey, nonce)

	return result

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
	decrypted := make([]byte, len(input))
	e := utils.AesCtr(decrypted, input, secretKey, nonce)

	if e != nil {
		panic("Danger danger")
	}

	if isAdmin(string(decrypted)) {
		fmt.Println("Success: Is Admin")
	} else {
		fmt.Println("Not Admin")
	}
}

func main() {

	//             prefix                  our data     suffix
	// |-------------------------------| |---------||-------------->
	//                                   |     |
	//                                   V     V
	// comment1=cooking %20MCs;userdata= 9admin9true;comm ent2=%20like%20a %20pound%20of%20 bacon
	// 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef

	encrypted := encrypt("9admin9true")

	encrypted[32] = encrypted[32] ^ 2 // 0011 1001 (9) ^ 0000 0010 (2) = 0011 1011 (;)
	encrypted[38] = encrypted[38] ^ 4 // 0011 1001 (9) ^ 0000 0100 (4) = 0011 1101 (=)


	decryptAndCheck(encrypted)
}


