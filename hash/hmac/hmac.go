package hmac

import (
	"cryptopals/hash/sha1"
	"cryptopals/xor"
)

var ipad, opad []byte

func init() {
	ipad, opad = make([]byte, 64), make([]byte, 64)
	for i := range ipad {
		ipad[i] = 0x36
		opad[i] = 0x5c
	}
}

// assumes 64 byte block size (true for SHA1 and MD4)
func HMAC(key, message []byte, hash func([]byte) []byte) []byte {
	if len(key) > 64 {
		key = hash(key)
	}
	if len(key) < 64 {
		key = append(key, make([]byte, 64 - len(key))...)
	}

	s, _ := xor.Fixed(key, ipad)
	s = append(s, message...)
	s = hash(s)
	t, _ := xor.Fixed(key, opad)
	t = append(t, s...)

	return hash(t)
}

func HMAC_SHA1(key, message []byte) []byte {
	return HMAC(key, message, sha1.Sum)
}
