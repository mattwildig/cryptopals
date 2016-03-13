package utils

import (
	"math/big"
	"errors"
	"crypto/rand"
)

var Zero = big.NewInt(0)
var One = big.NewInt(1)

type RSA struct {
	E, N, D *big.Int
}

// type PublicRSA struct {
// 	E, N *big.Int
// }

// type PrivateRSA struct {
// 	PublicRSA
// 	D *big.Int
// }

func CreateRSA(size, exp int) RSA {
	p_size := size / 2

	e := big.NewInt(int64(exp))

	var d *big.Int
	var n big.Int

	err := errors.New("Dummy start error")

	for err != nil {
		var et, t1, t2 big.Int
		p, _ := rand.Prime(rand.Reader, p_size)
		q, _ := rand.Prime(rand.Reader, p_size)

		n.Mul(p, q)
		et.Mul(t1.Sub(p, One), t2.Sub(q, One))

		d, err = InvMod(e, &et)
	}

	return RSA{e, &n, d}
}

func (rsa RSA) Encrypt(m *big.Int) *big.Int {
	var whocares big.Int
	return whocares.Exp(m, rsa.E, rsa.N)
}

func (rsa RSA) Decrypt(m *big.Int) *big.Int {
	var whocares big.Int
	return whocares.Exp(m, rsa.D, rsa.N)
}

func (rsa RSA) EncryptBytes(m []byte) []byte {
	bigint := new(big.Int)
	bigint.SetBytes(m)

	encrypted := rsa.Encrypt(bigint)

	return encrypted.Bytes()
}

func (rsa RSA) DecryptBytes(m []byte) []byte {
	bigint := new(big.Int)
	bigint.SetBytes(m)

	decrypted := rsa.Decrypt(bigint)

	return decrypted.Bytes()
}

// Param keyLen is in bits, converted in the function
func PKCS15Pad(data []byte, keyLen int) []byte {
	keyLen = keyLen / 8
	if len(data) > keyLen -11 { // 2 header bytes, min 8 random bytes, zero byte == 11 bytes
		panic("Data too long for padding")
	}
	padded := make([]byte, keyLen)
	padded[0] = 0x00
	padded[1] = 0x02
	for i := 2; i < keyLen - len(data) - 1; i++ {
		padded[i] = 0x03 // 3 chosen at random :-)
	}
	padded[keyLen - len(data) - 1] = 0x00
	copy(padded[keyLen - len(data):], data)

	return padded
}

func PKCS15Unpad(data []byte) []byte {
	var i int
	for i = 1; data[i] != 0x00; i++ {}
	return data[i+1:]
}
