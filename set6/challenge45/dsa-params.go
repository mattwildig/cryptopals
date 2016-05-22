package main

import (
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

	fmt.Println("Generated key with G = 0")

	message := []byte("This is a message.")

	sig := key.Sign(message)

	fmt.Println("Signed message, signature is:")

	fmt.Printf("\tR: %d\n", sig.R)
	fmt.Printf("\tS: %d\n", sig.S)

	public := key.Public

	v := public.Verify(message, sig)

	fmt.Printf("Real message verifies: %t\n", v)

	v = public.Verify([]byte("Fraudulant"), sig)

	fmt.Printf("False message verifies: %t\n", v)

	new_sig := dsa.Signature{big.NewInt(0), big.NewInt(10)}
	v = public.Verify([]byte("Banana"), new_sig)

	fmt.Printf("Arbitrary signature (with R = 0) verifies: %t\n", v)

	fmt.Println("---------------------------------------------------------------")

	key = dsa.CreateKey()
	fmt.Println("Created new key")

	sig = key.Sign(message)
	fmt.Println("Signed message, signature is:")
	fmt.Printf("\tR: %d\n", sig.R)
	fmt.Printf("\tS: %d\n", sig.S)

	public = key.Public

	v = public.Verify(message, sig)
	fmt.Printf("Signature verifies: %t\n", v)

	fmt.Println("Setting G to P + 1")
	public.G.Add(public.P, utils.One)

	v = public.Verify(message, sig)
	fmt.Printf("Signature still verifies: %t\n", v)

	fmt.Println("Creating \"magic\" signature, signature is:")

	z := big.NewInt(2)

	r := new(big.Int)
	r.Exp(public.Y, z, public.P).Mod(r, public.Q)
	s := new(big.Int)

	inv_z, _ := utils.InvMod(z, key.Q)
	s.Mul(r, inv_z).Mod(s, key.Q)

	sig2 := dsa.Signature{R: r, S: s}

	fmt.Printf("\tR: %d\n", sig2.R)
	fmt.Printf("\tS: %d\n", sig2.S)

	v = public.Verify(message, sig2)
	fmt.Printf("Magic signature verifies message: %t\n", v)

	v = public.Verify([]byte("Fraudulant"), sig2)

	fmt.Printf("False message verifies with magic signature: %t\n", v)

}
