package bigx

import "math/big"

var Zero = big.NewInt(0)
var One = big.NewInt(1)
var Two = big.NewInt(2)
var Three = big.NewInt(3)

var M = map[int64]*big.Int{
	0: Zero,
	1: One,
	2: Two,
	3: Three,
	4: big.NewInt(4),
}
