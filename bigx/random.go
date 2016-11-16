// Go provides two ways of creating random big ints, depending on
// whether you want "real" random (i.e. cryptographically random) or
// repeatably random (which is useful for testing.)
//
// Unfortunately the APIs are awkwardly different.
//
// This allows getting either, and chaging with a command line switch.
// Make sure you remember to call flag.Parse() in order to use this correctly.

package bigx

import (
	crand "crypto/rand"
	"flag"
	"math/big"
	"math/rand"
)

var (
	useCryptoRand bool
	mathRand *rand.Rand = rand.New(rand.NewSource(0))
)

func init() {
	flag.BoolVar(&useCryptoRand, "cr", false, "Use cryptographically random big Ints")
}

func GetRandInt(max *big.Int) *big.Int {
	if useCryptoRand {
		r, err := crand.Int(crand.Reader, max)
		if err != nil {
			panic(err.Error())
		}
		return r
	} else {
		r := new(big.Int)
		r.Rand(mathRand, max)
		return r
	}
}

func GetRandPrime(bits int) *big.Int {
	var p *big.Int
	var err error
	if useCryptoRand {
		p, err = crand.Prime(crand.Reader, bits)
	} else {
		p, err = crand.Prime(mathRand, bits)
	}

	if err != nil {
		panic("Error! An error has happened!")
	}

	return p
}
