package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"cryptopals/utils"
	"cryptopals/utils/dsa"
)

// Was main() when developing and testing
func test() {
	key := dsa.CreateKey()

	fmt.Println(key.X)

	message := []byte("Hello, this is a message")

	sig := key.Sign(message)

	pub := key.Public

	v := pub.Verify(message, sig)

	fmt.Println(v)

	fmt.Println(dsa.RecoverKeyFromSigningSecret(message, sig, pub, dsa.K))
}

func main() {

	r, s := new(big.Int), new(big.Int)
	r.SetString("548099063082341131477253921760299949438196259240", 10)
	s.SetString("857042759984254168557880549501802188789837994940", 10)
	var sig dsa.Signature
	sig.R = r
	sig.S = s

	var key dsa.Public
	key.Q, key.P, key.G = dsa.Q, dsa.P, dsa.G

	y := new(big.Int)
	y.SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
	key.Y = y

	message := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")

	fmt.Printf("Signature is valid for key and message: %v\n", key.Verify(message, sig))

	max_k := 1 << 16

	r_test, for_comparing := big.NewInt(1), new(big.Int)

	var k *big.Int = nil
	for lk :=1; lk <= max_k; lk++ {
		r_test.Mul(r_test, key.G)
		r_test.Mod(r_test, key.P)

		for_comparing.Mod(r_test, key.Q)
		// r_test.Exp(key.G, big.NewInt(int64(lk)), key.P)
		// r_test.Mod(r_test, key.Q)

		if for_comparing.Cmp(r) == 0 {
			k = big.NewInt(int64(lk))
			break
		}

		// if lk % 1000 == 0 {
		// 	fmt.Println(lk)
		// }
	}
	if k == nil {
		fmt.Println("Not found")
		return
	}

	fmt.Printf("Found k: %s\n", k)

	x := dsa.RecoverKeyFromSigningSecret(message, sig, key, k)

	fmt.Printf("x: %s\n", hex.EncodeToString(x.Bytes()))

	fmt.Printf("Hash of hex string of x: %s\n", hex.EncodeToString(utils.SHA1([]byte(hex.EncodeToString(x.Bytes())))))

	// var private dsa.Private
	// private.Public = key
	// private.X = x
}
