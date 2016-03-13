package utils

import (
	"math/big"
	// "fmt"
)

var two = big.NewInt(2)
var three = big.NewInt(3)

func CubeRoot(n *big.Int) *big.Int {

	// fmt.Println("In cuberoot")
	var x, diff big.Int
	diff.Set(two)

	x.Div(n, three)

	for diff.Cmp(One) > 0 {
		var n3, n2, _3n2, top, frac, next big.Int

		n3.Exp(&x, three, nil)
		n2.Exp(&x, two, nil)
		_3n2.Mul(&n2, two)

		top.Sub(&n3, n)
		frac.Div(&top, &_3n2)

		next.Sub(&x, &frac)

		diff.Abs(diff.Sub(&next, &x))
		// fmt.Println(&diff)

		x.Set(&next)

	}

	return &x

}