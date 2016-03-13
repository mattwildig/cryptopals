package main

import (
	"cryptopals/utils"
	"strings"
	"encoding/binary"
	"bytes"
	"fmt"
)

var key []byte
var message []byte = []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
var orig_hash []byte

func init() {
	key = utils.GenKey(1)
	orig_hash = utils.SHA1Sign(key, message)
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

func validate(data, signature []byte)  bool {
	calculated := utils.SHA1Sign(key, data)

	if ! bytes.Equal(calculated, signature) {
		fmt.Println("Bad signature!")
		return false
	}

	if isAdmin(string(data)) {
		fmt.Println("Admin access")
		return true
	} else {
		fmt.Println("Normal access")
		return false
	}
}

func extend_hash(hash, extra []byte) []byte {
	sha1 := utils.SHA1_t{}
	for i := 0; i < 5; i++ {
		//binary.BigEndian.PutUint32(result[i * 4:(i + 1) * 4], s.H[i])
		sha1.H[i] = binary.BigEndian.Uint32(hash[i * 4:(i + 1) * 4])
	}
	sha1.Data = extra
	sha1.Process()

	return sha1.Finalise()
}

var extra_message []byte = []byte(";admin=true")

func attempt(keylength int) bool {
	glue := utils.Bit_padding(len(message) + keylength)
	corrected := utils.Bit_padding(len(message) + keylength + len(glue) + len(extra_message))

	new_message := append(append(message, glue...), extra_message...)
	extra_to_hash := append(extra_message, corrected...)
	new_hash := extend_hash(orig_hash, extra_to_hash)

	return validate(new_message, new_hash)
}

func main() {
	for i := 0; i < 99; i++ {
		res := attempt(i)
		if res {
			fmt.Printf("Key length: %d\n", i)
			break
		}
	}
}