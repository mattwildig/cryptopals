package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"cryptopals/utils"
	"cryptopals/utils/dsa"
)

func main() {
	var key dsa.Private
	key.P, key.Q = dsa.P, dsa.Q
	key.G = big.NewInt(0)

	key = dsa.CreateKeyFromParams(key)

	fmt.Println("Generated key")

	message := []byte("This is a message.")

	sig := key.Sign(message)

	fmt.Println("Signed message")

	fmt.Println(sig.R)
	fmt.Println(sig.S)

	public := key.Public

	v := public.Verify(message, sig)

	fmt.Println(v)

	v = public.Verify([]byte("Fraudulant"), sig)

	fmt.Println(v)

	new_sig := dsa.Signature{big.NewInt(0), big.NewInt(10)}
	v = public.Verify([]byte("Banana"), new_sig)

	fmt.Println(v)
	fmt.Println()
	// fmt.Println("---------------------------------------------------------------")
	// fmt.Println()
	// scratch := new(big.Int)
	// fmt.Println(scratch.Mod(dsa.P, dsa.Q))

	// fmt.Println()
	fmt.Println("---------------------------------------------------------------")
	fmt.Println()

	key.G.Add(key.P, utils.One)
	key = dsa.CreateKeyFromParams(key)
	fmt.Println(hex.EncodeToString(key.Y.Bytes()))

	sig = key.Sign(message)
	fmt.Println(sig.R)
	fmt.Println(sig.S)

	// fmt.Println(key.Verify(message, sig))

	// WFT is the page saying here with all that s = r/z % q malarkey?
	// fmt.Println(key.Verify([]byte("Apple"), dsa.Signature{big.NewInt(1), big.NewInt(7)}))

	z := big.NewInt(2)
	inv_z, _ := utils.InvMod(z, key.Q)

	r := new(big.Int)
	r.Exp(key.Y, z, key.P).Mod(r, key.Q)
	s := new(big.Int)
	s.Mul(r, inv_z).Mod(s, key.Q)

	fmt.Println(r)
	fmt.Println(s)
	sig2 := dsa.Signature{R: r, S: utils.One}

	fmt.Println()
	fmt.Println(key.Verify([]byte("Banana"), sig2))
	fmt.Println(key.Verify([]byte("Apple"), sig2))
}
