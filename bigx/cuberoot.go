package bigx

import (
	"math/big"
)

func CubeRoot(n *big.Int) *big.Int {

	var x, diff big.Int
	diff.Set(Two)

	x.Div(n, Three)

	for diff.Cmp(One) > 0 {
		var n3, n2, _3n2, top, frac, next big.Int

		n3.Exp(&x, Three, nil)
		n2.Exp(&x, Two, nil)
		_3n2.Mul(&n2, Two)

		top.Sub(&n3, n)
		frac.Div(&top, &_3n2)

		next.Sub(&x, &frac)

		diff.Abs(diff.Sub(&next, &x))
		// fmt.Println(&diff)

		x.Set(&next)

	}

	return &x

}
