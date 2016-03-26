package main

import (
	"encoding/binary"
	"fmt"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

var step int
var errors bool = false

func ithBit(num uint32, i uint) uint32 {
	return (num & uint32(1 << i)) >> i
}

func assertEqual(word, other uint32, pos uint) {
	if ithBit(word, pos) != ithBit(other, pos) {
		text.PrintRed(fmt.Sprintf("Bit at pos %d not equal in step %d", pos, step))
		errors = true
	}
}

func assertZero(word uint32, pos uint) {
	if ithBit(word, pos) != 0 {
		text.PrintRed(fmt.Sprintf("Bit at pos %d not zero in step %d", pos, step))
		errors = true
	}
}

func assertOne(word uint32, pos uint) {
	if ithBit(word, pos) != 1 {
		text.PrintRed(fmt.Sprintf("Bit at pos %d not one in step %d", pos, step))
		errors = true
	}
}

// Perform first round of hashing, ensuring all first round
// conditions still hold
func ensureFirstRound(block []byte) {
	var words [16]uint32

	// hard code initial MD4 state for now
	a, b, c, d := utils.H0, utils.H1, utils.H2, utils.H3

	for i := 0; i < 16; i++ {
		words[i] = binary.BigEndian.Uint32(block[i * 4: (i + 1) * 4])
	}

	// a1,7 = b0,7
	step = 1
	a = leftrotate(a + f(b,c,d) + words[0], 3)    // as md4
	assertEqual(a, b, 6)

	// d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
	step++
	d = leftrotate(d + f(a,b,c) + words[1], 7)
	assertZero(d, 6)
	assertEqual(d, a, 7)
	assertEqual(d, a, 10)

	// c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
	step++
	c = leftrotate(c + f(d,a,b) + words[2], 11)
	assertOne(c, 6)

	// b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
	step++
	b = leftrotate(b + f(c,d,a) + words[3], 19)
	assertOne(b, 6)
	assertZero(b, 7)
	assertZero(b, 10)
	assertZero(b, 25)

	// a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
	step++
	a = leftrotate(a + f(b,c,d) + words[4], 3)
	assertOne(a, 7)
	assertOne(a, 10)
	assertZero(a, 25)
	assertEqual(a, b, 13)

	// d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
	step++
	d = leftrotate(d + f(a,b,c) + words[5], 7)
	assertZero(d, 13)
	assertEqual(d, a, 18)
	assertEqual(d, a, 19)
	assertEqual(d, a, 20)
	assertEqual(d, a, 21)
	assertOne(d, 25)

	// c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
	step++
	c = leftrotate(c + f(d,a,b) + words[6], 11)
	assertEqual(c, d, 12)
	assertZero(c, 13)
	assertEqual(c, d, 14)
	assertZero(c, 18)
	assertZero(c, 19)
	assertOne(c, 20)
	assertZero(c, 21)

	// b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
	step++
	b = leftrotate(b + f(c,d,a) + words[7], 19)
	assertOne(b, 12)
	assertOne(b, 13)
	assertZero(b, 14)
	assertEqual(b, c, 16)
	assertZero(b, 18)
	assertZero(b, 19)
	assertZero(b, 20)
	assertZero(b, 21)

	// a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0, a3,20 = 0, a3,21 = 0,
	// a3,23 = b2,23 a3,22 = 1, a3,26 = b2,26
	step++
	a = leftrotate(a + f(b,c,d) + words[8], 3)
	assertOne(a, 12)
	assertOne(a, 13)
	assertOne(a, 14)
	assertZero(a, 16)
	assertZero(a, 18)
	assertZero(a, 19)
	assertZero(a, 20)
	assertEqual(a, b, 22)
	assertOne(a, 21)
	assertEqual(a, b, 25)

	// d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0,
	// d3,26 = 1, d3,30 = a3,30
	step++
	d = leftrotate(d + f(a,b,c) + words[9], 7)
	assertOne(d, 12)
	assertOne(d, 13)
	assertOne(d, 14)
	assertZero(d, 16)
	assertZero(d, 19)
	assertOne(d, 20)
	assertOne(d, 21)
	assertZero(d, 22)
	assertOne(d, 25)
	assertEqual(d, a, 29)

	// c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
	step++
	c = leftrotate(c + f(d,a,b) + words[10], 11)
	assertOne(c, 16)
	assertZero(c, 19)
	assertZero(c, 20)
	assertZero(c, 21)
	assertZero(c, 22)
	assertZero(c, 25)
	assertOne(c, 29)
	assertEqual(c, d, 31)

	// b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
	step++
	b = leftrotate(b + f(c,d,a) + words[11], 19)
	assertZero(b, 19)
	assertOne(b, 20)
	assertOne(b, 21)
	assertEqual(b, c, 22)
	assertOne(b, 25)
	assertZero(b, 29)
	assertZero(b, 31)

	// a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
	step++
	a = leftrotate(a + f(b,c,d) + words[12], 3)
	assertZero(a, 22)
	assertZero(a, 25)
	assertEqual(a, b, 26)
	assertEqual(a, b, 28)
	assertOne(a, 29)
	assertZero(a, 31)

	// d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
	step++
	d = leftrotate(d + f(a,b,c) + words[13], 7)
	assertZero(d, 22)
	assertZero(d, 25)
	assertOne(d, 26)
	assertOne(d, 28)
	assertZero(d, 29)
	assertOne(d, 31)

	// c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
	step++
	c = leftrotate(c + f(d,a,b) + words[14], 11)
	assertEqual(c, d, 18)
	assertOne(c, 22)
	assertOne(c, 25)
	assertZero(c, 26)
	assertZero(c, 28)
	assertZero(c, 29)

	// b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
	step++
	b = leftrotate(b + f(c,d,a) + words[15], 19)
	assertZero(b, 18)
	assertOne(b, 25)
	assertOne(b, 26)
	assertOne(b, 28)
	assertZero(b, 29)

	if errors {
		text.PrintRed("Round one conditions did not hold")
	} else {
		text.PrintGreen("Round one conditions held")
	}
}
