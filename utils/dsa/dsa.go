package dsa

import (
	"crypto/rand"
	"math/big"

	"cryptopals/utils"
)

var (
	H func([]byte) []byte
	Q, P, G *big.Int = new(big.Int), new(big.Int), new(big.Int)
)

var K *big.Int

func init() {
	H = utils.SHA1
	Q.SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	P.SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
	G.SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
}

type Public struct {
	P, Q, G, Y *big.Int
}

type Private struct {
	Public
	X *big.Int
}

type Signature struct {
	R, S *big.Int
}

func CreateKey() Private {
	key := Private{Public:Public{P: P, Q: Q, G: G}}
	return CreateKeyFromParams(key)
}

func CreateKeyFromParams(key Private) Private {
	for {
		var err error
		key.X, err = rand.Int(rand.Reader, key.Q)
		if err != nil {
			panic("Blerrgg!!")
		}
		if key.X.Cmp(utils.Zero) != 0 {
			break
		}
	}

	// y = g ** x % p
	key.Y = new(big.Int)
	key.Y.Exp(key.G, key.X, key.P)

	return key
}

func hashBytesToBigInt(data []byte) *big.Int {
	hsh_bytes := H(data)
	bigInt := new(big.Int)
	bigInt.SetBytes(hsh_bytes)

	return bigInt
}

func (key Private) Sign(data []byte) Signature {
	for {
		// random k, 0 < k < q
		k, err := rand.Int(rand.Reader, key.Q)
		if err != nil {
			panic("Blerrgg!!")
		}
		if utils.BigZero(k) {
			continue
		}

		K = k // for testing key recovery

		// r = g ** k % p % q
		r := new(big.Int)
		r.Exp(key.G, k, key.P)
		r.Mod(r, key.Q)

		// if utils.BigZero(r) {
		// 	continue
		// }

		inv_k, e := utils.InvMod(k, key.Q)
		if e != nil {
			panic("Blergelburp")
		}
		hsh := hashBytesToBigInt(data)

		// s = (k ** -1) (H(m) + xr) % q
		s := new(big.Int)
		s.Mul(key.X, r)
		s.Add(s, hsh)
		s.Mul(s, inv_k)
		s.Mod(s, key.Q)

		if utils.BigZero(s) {
			continue
		}

		return Signature{r, s}
	}

}

// copy pasted from above - refactor
func (key Private) SignWithK(data []byte, k *big.Int) Signature {
	for {
		// r = g ** k % p % q
		r := new(big.Int)
		r.Exp(key.G, k, key.P)
		r.Mod(r, key.Q)

		if utils.BigZero(r) {
			continue
		}

		inv_k, e := utils.InvMod(k, key.Q)
		if e != nil {
			panic("Blergelburp")
		}
		hsh := hashBytesToBigInt(data)

		// s = (k ** -1) (H(m) + xr) % q
		s := new(big.Int)
		s.Mul(key.X, r)
		s.Add(s, hsh)
		s.Mul(s, inv_k)
		s.Mod(s, key.Q)

		if utils.BigZero(s) {
			continue
		}

		return Signature{r, s}
	}

}

func betweenZeroAnd(x, bound *big.Int) bool {
	if x.Cmp(utils.Zero) != 1 || x.Cmp(bound) != -1 {
		return false
	}
	return true
}

func (key Public) Verify(data []byte, sig Signature) bool {
	// if ! betweenZeroAnd(sig.R, key.Q) {
	// 	return false
	// }

	// if ! betweenZeroAnd(sig.S, key.Q) {
	// 	return false
	// }

	// w = s(-1) % q
	w, _ := utils.InvMod(sig.S, key.Q)

	hsh := hashBytesToBigInt(data)

	// u1 = H(m).w % q
	u1 := new(big.Int)
	u1.Mul(hsh, w)
	u1.Mod(u1, key.Q)

	// u2 = rw % q
	u2 := new(big.Int)
	u2.Mul(sig.R, w)
	u2.Mod(u2, key.Q)

	// v = (g ** u1)(y ** u2) %p % q
	v1 := new(big.Int)
	v1.Exp(key.G, u1, key.P)

	v2 := new(big.Int)
	v2.Exp(key.Y, u2, key.P)

	v := new(big.Int)
	v.Mul(v1, v2)
	v.Mod(v, key.P)
	v.Mod(v, key.Q)

	return v.Cmp(sig.R) == 0
}

func RecoverKeyFromSigningSecret(message []byte, sig Signature, key Public, k *big.Int) *big.Int {
	// x = sk - H(m) / r % q
	x := new(big.Int)
	x.Mul(sig.S, k)
	x.Sub(x, hashBytesToBigInt(message))
	inv_r, _ := utils.InvMod(sig.R, key.Q)
	x.Mul(x, inv_r)
	x.Mod(x, key.Q)

	return x
}

func RecoverKFromRepeatedNonce(m1, m2 []byte, sig1, sig2 Signature, key Public) *big.Int {
	if sig1.R.Cmp(sig2.R) != 0 {
		panic("R values should be the same")
	}

	h1 := hashBytesToBigInt(m1)
	h2 := hashBytesToBigInt(m2)

	// k = (h1 - h2) / s1 - s2 % q
	h := new(big.Int)
	h.Sub(h1, h2)
	h.Mod(h, key.Q)

	s := new(big.Int)
	s.Sub(sig1.S, sig2.S)
	s.Mod(s, key.Q)

	inv_s, _ := utils.InvMod(s, key.Q)

	k := new(big.Int)
	k.Mul(h, inv_s)
	k.Mod(k, key.Q)

	return k
}

