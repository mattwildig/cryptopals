package utils

import (
	"math/big"
	"fmt"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)

func InvMod(x, n *big.Int) (*big.Int, error) {
	var r, r1, t, t1 big.Int
	t.SetInt64(0)
	t1.SetInt64(1)

	r.Set(n)
	r1.Set(x)

	for ! BigZero(&r1) {
		var q, rt, tt big.Int
		q.DivMod(&r, &r1, &rt)
		r.Set(&r1)
		r1.Set(&rt)
		tt.Sub(&t, tt.Mul(&q, &t1))
		t.Set(&t1)
		t1.Set(&tt)
	}

	if r.Cmp(one) > 0 {
		return nil, fmt.Errorf("x and n must be coprime (given %d, %d)", x, n)
	}

	if t.Cmp(zero) < 0 {
		return t.Add(&t, n), nil
	}
	return &t, nil
}

func BigEql(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}

func BigZero(a *big.Int) bool {
	var zero big.Int
	zero.SetInt64(0)
	return zero.Cmp(a) == 0
}