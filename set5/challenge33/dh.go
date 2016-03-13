package main

import (
	"math/rand"
	"fmt"
	// "math"
	"math/big"
)

const p_hex_string = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

var (
	p *big.Int = new(big.Int)
	g = big.NewInt(2)
)

func init() {
	_, err := fmt.Sscan(p_hex_string, p)
	if err != nil {
		fmt.Println(err)
	}
}

func main() {

	// fmt.Printf("%s\n", p)
	// fmt.Printf("%s\n", g)


	r := rand.New(rand.NewSource(2))

	var a, A, b, B, key1, key2 big.Int
	a.Rand(r, p)
	A.Exp(g, &a, p)

	b.Rand(r, p)
	B.Exp(g, &b, p)

	key1.Exp(&A, &b, p)
	key2.Exp(&B, &a, p)

	fmt.Printf("%s, %s\n", &a, &A)
	fmt.Printf("%s, %s\n", &b, &B)

	fmt.Printf("(A ** b) %% p = %s\n", &key1)
	fmt.Printf("(B ** a) %% p = %s\n", &key2)

}