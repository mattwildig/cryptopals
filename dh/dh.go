package dh

import (
	"math/big"
	"math/rand"
	"fmt"
)

const p_hex_string = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

var (
	P *big.Int = new(big.Int)
	G = big.NewInt(2)
)

var rand_ *rand.Rand = rand.New(rand.NewSource(1))

func init() {
	fmt.Sscan(p_hex_string, P)
}

type Key struct {
	P, G, Secret, Public *big.Int
}

func New() Key {
	var r Key
	r.P = new(big.Int)
	r.G = new(big.Int)
	r.Secret = new(big.Int)
	r.Public = new(big.Int)

	return r
}

func InitNew(p, g *big.Int) Key {
	r := New()
	r.P.Set(p)
	r.G.Set(g)
	r.Secret.Rand(rand_, p)
	r.Public.Exp(g, r.Secret, p)

	return r
}

func Secret(t Key, B *big.Int) *big.Int {
	return new(big.Int).Exp(B, t.Secret, t.P)
}
