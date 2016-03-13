package main

import (
	"cryptopals/utils"
	"math/big"
	"fmt"
)

var server = utils.CreateRSA(1024, 3)

func encrypt(message []byte) []byte {
	var m big.Int
	m.SetBytes(message)
	m.Set(server.Encrypt(&m))

	return m.Bytes()
}

func decrypt(message []byte) []byte {
	var m big.Int
	m.SetBytes(message)
	m.Set(server.Decrypt(&m))

	return m.Bytes()
}

func main() {
	message := []byte("Another Hi, this is a message blah")

	fmt.Printf("%q\n", message)

	c := encrypt(message)

	attacker(c)
}

func attacker(cipherText []byte) {
	s := big.NewInt(2)
	var c, c_prime, t, res big.Int
	c.SetBytes(cipherText)
	c_prime.Mul(t.Exp(s, server.E, server.N), &c)

	res.SetBytes(decrypt(c_prime.Bytes()))

	inv, err := utils.InvMod(s, server.N)
	if err != nil {
		fmt.Printf("Error calculating inv: %s", err)
	}
	res.Mul(&res, inv).Mod(&res, server.N)

	fmt.Printf("%q\n", res.Bytes())
}
