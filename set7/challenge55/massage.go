package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

// helpers funcs from md4.go
func f(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

// func g(x, y, z uint32) uint32 {
// 	return (x & y) | (x & z) | (y & z)
// }

// func h(x, y, z uint32) uint32 {
// 	return x ^ y ^ z
// }

func leftrotate(x uint32, shift uint) uint32 {
	return (x << shift) | (x >> (32 - shift))
}

func rightrotate(x uint32, shift uint) uint32 {
	return (x >> shift) | (x << (32 - shift))
}

func ithBit(num uint32, i uint) uint32 {
	return (num ^ uint32(1 << i)) >> i
}

// Set bit at position pos in word to be equal to that bit
// in other, and return it
func setBitEqual(word, other uint32, pos uint) uint32 {
	target := uint32(1) << pos
	set := target & other
	mask := ^target

	return (mask & word) | set
}

func firstRoundMassage(block []byte) [16]uint32{

	var words [16]uint32

	// hard code initial MD4 state for now
	a, b, c, d := utils.H0, utils.H1, utils.H2, utils.H3
	var next uint32

	for i := 0; i < 16; i++ {
		words[i] = binary.BigEndian.Uint32(block[i * 4: (i + 1) * 4])
	}

	// a1,7 = b0,7
	next = leftrotate(a + f(b,c,d) + words[0], 3)    // as md4
	next = setBitEqual(next, b, 6)                   // "fix" new val
	words[0] = rightrotate(next, 3) - a - f(b, c, d) // massage input so it will give desired result
	a = next

	// d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
	next = leftrotate(d + f(a,b,c) + words[1], 7)
	next &^= 1 << 6
	next = setBitEqual(next, a, 7)
	next = setBitEqual(next, a, 10)
	words[1] = rightrotate(next, 7) - d - f(a, b, c)
	d = next

	// c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
	next = leftrotate(c + f(d,a,b) + words[2], 11)
	next |= 1 << 6
	next |= 1 << 7
	next &^= 1 << 10
	next = setBitEqual(next, d, 25)
	words[2] = rightrotate(next, 11) - c - f(d, a, b)
	c = next

	// b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
	next = leftrotate(b + f(c,d,a) + words[3], 19)
	next |= 1 << 6
	next &^= 1 << 7
	next &^= 1 << 11
	next &^= 1 << 25
	words[3] = rightrotate(next, 19) - b - f(c, d, a)
	b = next

	// a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
	next = leftrotate(a + f(b,c,d) + words[4], 3)
	next |= 1 << 7
	next |= 1 << 10
	next &^= 1 << 25
	next = setBitEqual(next, b, 13)
	words[4] = rightrotate(next, 3) - a - f(b, c, d)
	a = next

	// d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
	next = leftrotate(d + f(a,b,c) + words[5], 7)
	next &^= 1 << 13
	next = setBitEqual(next, a, 18)
	next = setBitEqual(next, a, 19)
	next = setBitEqual(next, a, 20)
	next = setBitEqual(next, a, 21)
	next |= 1 << 25
	words[5] = rightrotate(next, 7) - d - f(a, b, c)
	d = next

	// c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
	next = leftrotate(c + f(d,a,b) + words[6], 11)
	next = setBitEqual(next, d, 12)
	next &^= 1 << 13
	next = setBitEqual(next, d, 14)
	next &^= 1 << 18
	next &^= 1 << 19
	next |= 1 << 20
	next &^= 1 << 21
	words[6] = rightrotate(next, 11) - c - f(d, a, b)
	c = next

	// b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
	next = leftrotate(b + f(c,d,a) + words[7], 19)
	next |= 1 << 12
	next |= 1 << 13
	next &^= 1 << 14
	next = setBitEqual(next, c, 16)
	next &^= 1 << 18
	next &^= 1 << 19
	next &^= 1 << 20
	next &^= 1 << 21
	words[7] = rightrotate(next, 19) - b - f(c, d, a)
	b = next

	// a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0, a3,20 = 0, a3,21 = 0,
	// a3,23 = b2,23 a3,22 = 1, a3,26 = b2,26
	next = leftrotate(a + f(b,c,d) + words[8], 3)
	next |= 1 << 12
	next |= 1 << 13
	next |= 1 << 14
	next &^= 1 << 16
	next &^= 1 << 18
	next &^= 1 << 19
	next &^= 1 << 20
	next = setBitEqual(next, b, 22)
	next |= 1 << 21
	next = setBitEqual(next, b, 25)
	words[8] = rightrotate(next, 3) - a - f(b, c, d)
	a = next

	// d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0,
	// d3,26 = 1, d3,30 = a3,30
	next = leftrotate(d + f(a,b,c) + words[9], 7)
	next |= 1 << 12
	next |= 1 << 13
	next |= 1 << 14
	next &^= 1 << 16
	next &^= 1 << 19
	next |= 1 << 20
	next |= 1 << 21
	next &^= 1 << 22
	next |= 1 << 25
	next = setBitEqual(next, a, 29)
	words[9] = rightrotate(next, 7) - d - f(a, b, c)
	d = next

	// c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
	next = leftrotate(c + f(d,a,b) + words[10], 11)
	next |= 1 << 16
	next &^= 1 << 19
	next &^= 1 << 20
	next &^= 1 << 21
	next &^= 1 << 22
	next &^= 1 << 25
	next |= 1 << 29
	next = setBitEqual(next, d, 31)
	words[10] = rightrotate(next, 11) - c - f(d, a, b)
	c = next

	// b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
	next = leftrotate(b + f(c,d,a) + words[11], 19)
	next &^= 1 << 19
	next |= 1 << 20
	next |= 1 << 21
	next = setBitEqual(next, c, 22)
	next |= 1 << 25
	next &^= 1 << 29
	next &^= 1 << 31
	words[11] = rightrotate(next, 19) - b - f(c, d, a)
	b = next

	// a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
	next = leftrotate(a + f(b,c,d) + words[12], 3)
	next &^= 1 << 22
	next &^= 1 << 25
	next = setBitEqual(next, b, 26)
	next = setBitEqual(next, b, 28)
	next |= 1 << 29
	next &^= 1 << 31
	words[12] = rightrotate(next, 3) - a - f(b, c, d)
	a = next

	// d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
	next = leftrotate(d + f(a,b,c) + words[13], 7)
	next &^= 1 << 22
	next &^= 1 << 25
	next |= 1 << 26
	next |= 1 << 28
	next &^= 1 << 29
	next |= 1 << 31
	words[13] = rightrotate(next, 7) - d - f(a, b, c)
	d = next

	// c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
	next = leftrotate(c + f(d,a,b) + words[14], 11)
	next = setBitEqual(next, d, 18)
	next |= 1 << 22
	next |= 1 << 25
	next &^= 1 << 26
	next &^= 1 << 28
	next &^= 1 << 29
	words[14] = rightrotate(next, 11) - c - f(d, a, b)
	c = next

	// b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
	next = leftrotate(b + f(c,d,a) + words[15], 19)
	next &^= 1 << 18
	next |= 1 << 25
	next |= 1 << 26
	next |= 1 << 28
	next &^= 1 << 29
	words[15] = rightrotate(next, 19) - b - f(c, d, a)
	b = next

	return words
}

func joinWords(words [16]uint32) []byte {
	ret := make([]byte, 64)
	p := ret
	for _, w := range(words) {
		binary.BigEndian.PutUint32(p, w)
		p = p[4:]
	}
	return ret
}

func testBlockIsUnchanged(blk []byte) {
	ary := firstRoundMassage(blk)
	massaged := joinWords(ary)

	if bytes.Equal(blk, massaged) {
		text.PrintGreen("Massaged hash is unchanged")
	} else {
		text.PrintRed("Massaged text differs:")
		fmt.Printf("  original:  %s\n", hex.EncodeToString(blk))
		fmt.Printf("  massaged:  %s\n", hex.EncodeToString(massaged))
	}
}

func main() {
	colliding_hashes_from_paper := []string{
	    "4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9",
	    "4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69",
	}

	for _, s := range(colliding_hashes_from_paper) {
		s = strings.Replace(s, " ", "", -1)
		decoded, err := hex.DecodeString(s)
		if err != nil {
			text.PrintRed("Invalid hex string:")
			fmt.Println(err)
			continue
		}

		testBlockIsUnchanged(decoded)
	}
}
