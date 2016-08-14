package bigx

import (
	"math/big"
	"fmt"
)

func InvMod(x, n *big.Int) (*big.Int, error) {
	var r, r1, t, t1 big.Int
	t.SetInt64(0)
	t1.SetInt64(1)

	r.Set(n)
	r1.Set(x)

	for !IsZero(&r1) {
		var q, rt, tt big.Int
		q.DivMod(&r, &r1, &rt)
		r.Set(&r1)
		r1.Set(&rt)
		tt.Sub(&t, tt.Mul(&q, &t1))
		t.Set(&t1)
		t1.Set(&tt)
	}

	if r.Cmp(One) > 0 {
		return nil, fmt.Errorf("x and n must be coprime (given %d, %d)", x, n)
	}

	if t.Cmp(Zero) < 0 {
		return t.Add(&t, n), nil
	}
	return &t, nil
}

func Equal(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}

func IsZero(a *big.Int) bool {
	return Zero.Cmp(a) == 0
}
