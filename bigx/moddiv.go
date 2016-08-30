package bigx

import (
	"math/big"
)

// Division (a / b) in GF(p)
func FieldDiv(a, b, p *big.Int) *big.Int{
	invB, e := InvMod(b, p)
	if e != nil {
		panic(e.Error())
	}

	r := new(big.Int)
	r.Mul(a, invB)
	r.Mod(r, p)

	return r
}
