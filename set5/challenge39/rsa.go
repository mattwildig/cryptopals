package main

import (
	"cryptopals/utils"
	"fmt"
	"math/big"
	// "crypto/rand"
)

var one = big.NewInt(1)

func main() {
	// p, _ := rand.Prime(rand.Reader, 512) //big.NewInt(3001)
	// q, _ := rand.Prime(rand.Reader, 512) //big.NewInt(3559)

	// var n, et, t1, t2 big.Int
	// n.Mul(p, q)
	// et.Mul(t1.Sub(p, one), t2.Sub(q, one))

	// e := big.NewInt(5)

	// d, err := utils.InvMod(e, &et)

	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	pair := utils.CreateRSA(1024, 3)

	fmt.Printf("n is %s\n", pair.N)

	// Public key is [e, n], private key is [d, n] 

	message := []byte("These are the days - it never rains but it pours")
	var secret big.Int
	secret.SetBytes(message)

	fmt.Printf("Message is %s\n", message)
	fmt.Printf("Message as int is %s\n", &secret)

	cipherText := pair.Encrypt(&secret)

	fmt.Printf("Ciphertext is %s\n", cipherText)

	var decoded = pair.Decrypt(cipherText)
	// decoded.Exp(cipherText, pair.D, pair.N)

	fmt.Printf("Decoded is %s\n", decoded.Bytes())
}