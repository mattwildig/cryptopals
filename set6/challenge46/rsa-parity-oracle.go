package main

import (
	"encoding/base64"
	"fmt"
	"math/big"

	"cryptopals/utils"
)

var secretKey utils.RSA = utils.CreateRSA(1024, 3)
var publicKey utils.RSA
var message []byte

var base64Message = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="

// var two = big.NewInt(2)

func init() {
	publicKey.E = secretKey.E
	publicKey.N = secretKey.N

	// message = secretKey.EncryptBytes([]byte("This is a secret message"))
	message, _ = base64.StdEncoding.DecodeString(base64Message)
	message = secretKey.EncryptBytes(message)

}

// true if even
func ParityOracle(message *big.Int) bool {

	decrypted := secretKey.Decrypt(message)

	return decrypted.Bit(0) == 0
}

func main() {
	m := new(big.Int)
	m.SetBytes(message)

	doubleFactor := new(big.Int)
	doubleFactor.Exp(big.NewInt(2), publicKey.E, publicKey.N)

	// lower, upper := big.NewInt(0), new(big.Int).Set(publicKey.N)
	lower, upper := big.NewRat(0,1), new(big.Rat).SetInt(publicKey.N)
	// upper.Sub(upper, utils.One)
	times := publicKey.N.BitLen()
	times++

	two := big.NewRat(2,1)
	var upperInt = new(big.Int)

	// for lower.Cmp(upper) != 0 {
	for {

		m.Mul(m, doubleFactor).Mod(m, publicKey.N)

		// var mid, rem big.Int
		// mid.Add(upper, lower).DivMod(&mid, two, &rem) //.Add(mid, utils.One)
		// mid.Add(&mid, &rem)
		var mid big.Rat
		mid.Add(upper, lower).Quo(&mid, two)

		even := ParityOracle(m)
		if even {
			// No wrap - plaintext is in lower half, decrease upper bound
			upper.Set(&mid)
		} else {
			// Wrap - plaintext in upper range, increase lower bound
			lower.Set(&mid)
		}
		upperInt.Div(upper.Num(), upper.Denom())

		// fmt.Print("\r")
		fmt.Printf("%q\n", upperInt.Bytes())
		// fmt.Println(upper)
		// fmt.Println(lower)
		// fmt.Println(m)
		times--
		if times == 0 {
			break
		}
	}
	// fmt.Println(new(big.Int).SetBytes([]byte("This is a secret message")))
	fmt.Println()
}