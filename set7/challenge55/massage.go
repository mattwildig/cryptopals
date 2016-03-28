package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	// "strings"

	"cryptopals/utils"
	"cryptopals/utils/text"
)

type state struct {
	a, b, c, d [11]uint32
}

type messageWords [16]uint32

// helpers funcs from md4.go
func f(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func g(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

// func h(x, y, z uint32) uint32 {
// 	return x ^ y ^ z
// }

func leftrotate(x uint32, shift uint) uint32 {
	return (x << shift) | (x >> (32 - shift))
}

func rightrotate(x uint32, shift uint) uint32 {
	return (x >> shift) | (x << (32 - shift))
}

// Set bit at position pos in word to be equal to that bit
// in other, and return it
func setBitEqual(word, other uint32, pos uint) uint32 {
	target := uint32(1) << pos
	set := target & other
	mask := ^target

	return (mask & word) | set
}

func firstRoundMassage(words messageWords, s state) ([16]uint32, state){

	// for easy access
	a, b, c, d := &s.a, &s.b, &s.c, &s.d

	// a1,7 = b0,7
	a[1] = leftrotate(a[0] + f(b[0], c[0], d[0]) + words[0], 3)    // as md4
	a[1] = setBitEqual(a[1], b[0], 6)                   // "fix" new val
	words[0] = rightrotate(a[1], 3) - a[0] - f(b[0], c[0], d[0]) // massage input so it will give desired result

	// d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
	d[1] = leftrotate(d[0] + f(a[1], b[0], c[0]) + words[1], 7)
	d[1] &^= 1 << 6
	d[1] = setBitEqual(d[1], a[1], 7)
	d[1] = setBitEqual(d[1], a[1], 10)
	words[1] = rightrotate(d[1], 7) - d[0] - f(a[1], b[0], c[0])

	// c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
	c[1] = leftrotate(c[0] + f(d[1], a[1], b[0]) + words[2], 11)
	c[1] |= 1 << 6
	c[1] |= 1 << 7
	c[1] &^= 1 << 10
	c[1] = setBitEqual(c[1], d[1], 25)
	words[2] = rightrotate(c[1], 11) - c[0] - f(d[1], a[1], b[0])

	// b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
	b[1] = leftrotate(b[0] + f(c[1], d[1], a[1]) + words[3], 19)
	b[1] |= 1 << 6
	b[1] &^= 1 << 7
	b[1] &^= 1 << 10
	b[1] &^= 1 << 25
	words[3] = rightrotate(b[1], 19) - b[0] - f(c[1], d[1], a[1])

	// a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
	a[2] = leftrotate(a[1] + f(b[1], c[1], d[1]) + words[4], 3)
	a[2] |= 1 << 7
	a[2] |= 1 << 10
	a[2] &^= 1 << 25
	a[2] = setBitEqual(a[2], b[1], 13)
	words[4] = rightrotate(a[2], 3) - a[1] - f(b[1], c[1], d[1])

	// d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
	d[2] = leftrotate(d[1] + f(a[2], b[1], c[1]) + words[5], 7)
	d[2] &^= 1 << 13
	d[2] = setBitEqual(d[2], a[2], 18)
	d[2] = setBitEqual(d[2], a[2], 19)
	d[2] = setBitEqual(d[2], a[2], 20)
	d[2] = setBitEqual(d[2], a[2], 21)
	d[2] |= 1 << 25
	words[5] = rightrotate(d[2], 7) - d[1] - f(a[2], b[1], c[1])

	// c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
	c[2] = leftrotate(c[1] + f(d[2], a[2], b[1]) + words[6], 11)
	c[2] = setBitEqual(c[2], d[2], 12)
	c[2] &^= 1 << 13
	c[2] = setBitEqual(c[2], d[2], 14)
	c[2] &^= 1 << 18
	c[2] &^= 1 << 19
	c[2] |= 1 << 20
	c[2] &^= 1 << 21
	words[6] = rightrotate(c[2], 11) - c[1] - f(d[2], a[2], b[1])

	// b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
	b[2] = leftrotate(b[1] + f(c[2], d[2], a[2]) + words[7], 19)
	b[2] |= 1 << 12
	b[2] |= 1 << 13
	b[2] &^= 1 << 14
	b[2] = setBitEqual(b[2], c[2], 16)
	b[2] &^= 1 << 18
	b[2] &^= 1 << 19
	b[2] &^= 1 << 20
	b[2] &^= 1 << 21
	words[7] = rightrotate(b[2], 19) - b[1] - f(c[2], d[2], a[2])

	// a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0, a3,20 = 0, a3,21 = 0,
	// a3,23 = b2,23 a3,22 = 1, a3,26 = b2,26
	a[3] = leftrotate(a[2] + f(b[2], c[2], d[2]) + words[8], 3)
	a[3] |= 1 << 12
	a[3] |= 1 << 13
	a[3] |= 1 << 14
	a[3] &^= 1 << 16
	a[3] &^= 1 << 18
	a[3] &^= 1 << 19
	a[3] &^= 1 << 20
	a[3] = setBitEqual(a[3], b[2], 22)
	a[3] |= 1 << 21
	a[3] = setBitEqual(a[3], b[2], 25)
	words[8] = rightrotate(a[3], 3) - a[2] - f(b[2], c[2], d[2])

	// d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0,
	// d3,26 = 1, d3,30 = a3,30
	d[3] = leftrotate(d[2] + f(a[3], b[2], c[2]) + words[9], 7)
	d[3] |= 1 << 12
	d[3] |= 1 << 13
	d[3] |= 1 << 14
	d[3] &^= 1 << 16
	d[3] &^= 1 << 19
	d[3] |= 1 << 20
	d[3] |= 1 << 21
	d[3] &^= 1 << 22
	d[3] |= 1 << 25
	d[3] = setBitEqual(d[3], a[3], 29)
	words[9] = rightrotate(d[3], 7) - d[2] - f(a[3], b[2], c[2])

	// c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
	c[3] = leftrotate(c[2] + f(d[3], a[3], b[2]) + words[10], 11)
	c[3] |= 1 << 16
	c[3] &^= 1 << 19
	c[3] &^= 1 << 20
	c[3] &^= 1 << 21
	c[3] &^= 1 << 22
	c[3] &^= 1 << 25
	c[3] |= 1 << 29
	c[3] = setBitEqual(c[3], d[3], 31)
	words[10] = rightrotate(c[3], 11) - c[2] - f(d[3], a[3], b[2])

	// b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
	b[3] = leftrotate(b[2] + f(c[3], d[3], a[3]) + words[11], 19)
	b[3] &^= 1 << 19
	b[3] |= 1 << 20
	b[3] |= 1 << 21
	b[3] = setBitEqual(b[3], c[3], 22)
	b[3] |= 1 << 25
	b[3] &^= 1 << 29
	b[3] &^= 1 << 31
	words[11] = rightrotate(b[3], 19) - b[2] - f(c[3], d[3], a[3])

	// a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
	a[4] = leftrotate(a[3] + f(b[3], c[3], d[3]) + words[12], 3)
	a[4] &^= 1 << 22
	a[4] &^= 1 << 25
	a[4] = setBitEqual(a[4], b[3], 26)
	a[4] = setBitEqual(a[4], b[3], 28)
	a[4] |= 1 << 29
	a[4] &^= 1 << 31
	words[12] = rightrotate(a[4], 3) - a[3] - f(b[3], c[3], d[3])

	// d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
	d[4] = leftrotate(d[3] + f(a[4], b[3], c[3]) + words[13], 7)
	d[4] &^= 1 << 22
	d[4] &^= 1 << 25
	d[4] |= 1 << 26
	d[4] |= 1 << 28
	d[4] &^= 1 << 29
	d[4] |= 1 << 31
	words[13] = rightrotate(d[4], 7) - d[3] - f(a[4], b[3], c[3])

	// c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
	c[4] = leftrotate(c[3] + f(d[4], a[4], b[3]) + words[14], 11)
	c[4] = setBitEqual(c[4], d[4], 18)
	c[4] |= 1 << 22
	c[4] |= 1 << 25
	c[4] &^= 1 << 26
	c[4] &^= 1 << 28
	c[4] &^= 1 << 29
	words[14] = rightrotate(c[4], 11) - c[3] - f(d[4], a[4], b[3])

	// b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
	b[4] = leftrotate(b[3] + f(c[4], d[4], a[4]) + words[15], 19)
	b[4] &^= 1 << 18
	b[4] |= 1 << 25
	b[4] |= 1 << 26
	b[4] |= 1 << 28
	b[4] &^= 1 << 29
	words[15] = rightrotate(b[4], 19) - b[3] - f(c[4], d[4], a[4])

	return words, s
}

func bitPosEqual(a, b uint32, pos uint) bool {
	return a & (1 << pos) == b & (1 << pos)
}

func furtherModifications(words messageWords, s state) messageWords {

	a, b, c, d := &s.a, &s.b, &s.c, &s.d

	// a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
	a[5] = leftrotate(a[4] + g(b[4], c[4], d[4]) + words[0] + 0x5A827999, 3)
	a1p := a[1]

	if !bitPosEqual(a[5], c[4], 18) {
		fmt.Println("a5 and c5 differ at bit 18")
		words[0] ^= 1 << 15
		a1p ^= (1 << 18)
		a[5] = leftrotate(a[4] + g(b[4], c[4], d[4]) + words[0] + 0x5A827999, 3)
	}
	if ithBit(a[5], 25) != 1 {
		fmt.Println("25th bit of a5 wrong")

		words[0] ^= 1 << 22
		a1p ^= (1 << 25)
		a[5] = leftrotate(a[4] + g(b[4], c[4], d[4]) + words[0] + 0x5A827999, 3)
	}
	if ithBit(a[5], 26) != 0 {
		fmt.Println("26th bit of a5 wrong")

		words[0] ^= 1 << 23
		a1p ^= (1 << 26)
		a[5] = leftrotate(a[4] + g(b[4], c[4], d[4]) + words[0] + 0x5A827999, 3)
	}
	if ithBit(a[5], 28) != 1 {
		fmt.Println("28th bit of a5 wrong")

		words[0] ^= 1 << 25
		a1p ^= (1 << 28)
		a[5] = leftrotate(a[4] + g(b[4], c[4], d[4]) + words[0] + 0x5A827999, 3)
	}
	if ithBit(a[5], 31) != 1 {
		fmt.Println("31th bit of a5 wrong")

		words[0] ^= 1 << 28
		a1p ^= (1 << 31)
		a[5] = leftrotate(a[4] + g(b[4], c[4], d[4]) + words[0] + 0x5A827999, 3)
	}

	words[1] = rightrotate(d[1], 7) - d[0] - f(a1p, b[0], c[0])
	words[2] = rightrotate(c[1], 11) - c[0] - f(d[1], a1p, b[0])
	words[3] = rightrotate(b[1], 19) - b[0] - f(c[1], d[1], a1p)
	words[4] = rightrotate(a[2], 3) - a1p - f(b[1], c[1], d[1])

	return words
}

func blockToWords(block []byte) messageWords{

	if len(block) != 64 {
		text.PrintRed("Block length should be 64 bytes")
		panic("")
	}

	var words messageWords

	for i := 0; i < 16; i++ {
		words[i] = binary.BigEndian.Uint32(block[i * 4: (i + 1) * 4])
	}

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
	s := state{}
	s.a[0], s.b[0], s.c[0], s.d[0] = utils.H0, utils.H1, utils.H2, utils.H3

	ary, _ := firstRoundMassage(blockToWords(blk), s)
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
	// colliding_hashes_from_paper := []string{
	//     "4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9",
	//     "4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69",
	// }

	// for _, s := range(colliding_hashes_from_paper) {
	// 	s = strings.Replace(s, " ", "", -1)
	// 	decoded, err := hex.DecodeString(s)
	// 	if err != nil {
	// 		text.PrintRed("Invalid hex string:")
	// 		fmt.Println(err)
	// 		continue
	// 	}
	// 	testBlockIsUnchanged(decoded)

	// 	words := blockToWords(decoded)
	// 	ensureFirstRound(words)
	// }

	test_block := utils.GenKey(64)
	test_words := blockToWords(test_block)

	s := state{}
	s.a[0], s.b[0], s.c[0], s.d[0] = utils.H0, utils.H1, utils.H2, utils.H3
	massaged, s := firstRoundMassage(test_words, s)
	ensureFirstRound(massaged)
	ensureSecondRound(massaged, s)
	massaged = furtherModifications(massaged, s)
	ensureFirstRound(massaged)
	ensureSecondRound(massaged, s)

}
