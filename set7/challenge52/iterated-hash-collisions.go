package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"crypto/aes"
)

const AES_BLOCK_SIZE = 16

func padBlock(data []byte, length int) []byte {
	if len(data) > length {
		panic("Data too long to be padded")
	}
	padded := make([]byte, length)
	copy(padded, data)
	return padded
}

func singleBlockAES(key, data []byte) []byte {
	key = padBlock(key, AES_BLOCK_SIZE)
	data = padBlock(data, AES_BLOCK_SIZE)
	result := make([]byte, AES_BLOCK_SIZE)

	cipher, _ := aes.NewCipher(key)
	cipher.Encrypt(result, data)

	return result
}

var hashTwoBytes = makeHashFunction(make([]byte, 2))
var hashThreeBytes = makeHashFunction(make([]byte, 3))

func makeHashFunction(startState []byte) func([]byte) []byte {

	length := len(startState)

	return func(data []byte)[]byte {
		state := startState

		for len(data) > length {
			res := singleBlockAES(state, data[:length])
			state = res[:length]
			data = data[length:]
		}

		// final block
		data = padBlock(data, length)
		res := singleBlockAES(state, data[:length])
		return res[:length]
	}

}

func makeCombinedHashFunction(first, second func([]byte)[]byte) func([]byte)[]byte {
	return func(data []byte)[]byte {
		return append(first(data), second(data)...)
	}
}

// create a reusable compression func so we can reuse it lots
func makeCompressionFunction(state []byte, length int) func([]byte) []byte {

	state = padBlock(state, AES_BLOCK_SIZE)

	// use AES directly (not through our wrapper)
	cipher, _ := aes.NewCipher(state)

	return func(data []byte) []byte {
		if len(data) != length {
			panic(fmt.Sprintf("Incorrect data length for hash function: %d (exected %d)", len(data), length))
		}
		data = padBlock(data, AES_BLOCK_SIZE)
		result := make([]byte, AES_BLOCK_SIZE)
		cipher.Encrypt(result, data)

		return result[:length]
	}
}

func makeBufferFromInt(i, size int) []byte {
	res := make([]byte, size)
	binary.PutUvarint(res, uint64(i))

	return res
}

func findBlockCollision(f func([]byte) []byte, size int) ([]byte, []byte, []byte) {
	// stuff it, parrellel slices
	data := make([][]byte, 0)
	hashes := make([][]byte, 0)

	for i := 0; i < ((1 << uint(size * 8) - 1)); i++ {
		cand := makeBufferFromInt(i, size)
		hsh := f(cand)

		for i, current := range(hashes) {
			if bytes.Equal(hsh, current) {
				// fmt.Println(i)
				return cand, data[i], hsh
			}
		}
		data = append(data, cand)
		hashes = append(hashes, hsh)
	}
	panic("BLERGG")
}

// type pair struct {
// 	first, second []byte
// }

// func combinePairs(pairs []pair)[][]byte {

// 	if len(pairs) == 1 {
// 		return [][]byte{pairs[0].first, pairs[0].second}
// 	}

// 	results := make([][]byte, 0)

// 	for _, sub := range combinePairs(pairs[1:]) {
// 		t := append(pairs[0].first, sub...)
// 		results = append(results, t)
// 		t = append(pairs[0].second, sub...)
// 		results = append(results, t)
// 	}

// 	return results
// }

// Note: Careful how bits in puck and entries in pairs/result
// line up. Low bits (i.e. conceptually on the RHS correspond to
// early entries (i.e.  on the LHS))
func pickChunks(pairs [][][]byte, pick uint32) []byte {
	result := make([]byte, 0)

	for i := uint32(0); i < uint32(len(pairs)); i++ {
		chosen := ((1 << i) & pick) >> i
		// result[i] = pairs[i][chosen]
		result = append(result, pairs[i][chosen]...)
	}

	return result
}

func combinePairs(pairs [][][]byte)[][]byte {
	var max uint32 = 1 << uint32(len(pairs))
	result := make([][]byte, 0)

	for i := uint32(0); i < max; i++ {
		result = append(result, pickChunks(pairs, i))
	}

	return result
}

func findMultipleCollisions(required, hashSize int) [][]byte {
	pairs := make([][][]byte, 0)
	state := make([]byte, hashSize)

	for count := 1; count < required;  {
		c := makeCompressionFunction(state, hashSize)
		first, second, hash := findBlockCollision(c, hashSize)
		pairs = append(pairs, [][]byte{first, second})
		state = hash
		count *=2
	}

	return combinePairs(pairs)
}

func findCollision(list [][]byte, f func([]byte)[]byte) (bool, []byte, []byte) {
	// O(n**2), yuck
	for i, cand := range list {
		hsh := f(cand)
		if i + 1 == len(list) {
			break
		}
		for _, d := range list[i+1:] {
			if bytes.Equal(hsh, f(d)) {
				return true, cand, d
			}
		}
	}
	return false, nil, nil
}

func main() {

	f := hashTwoBytes
	g := hashThreeBytes
	h := makeCombinedHashFunction(f, g)

	collisionsNeededInF := 1 << 11 // e ** (3 * 8)/2), bit size / 2 of g()
	list := findMultipleCollisions(collisionsNeededInF, 2)

	found, d1, d2 := findCollision(list, g)

	if found {
		fmt.Printf("%q: %q, %q, %q\n", d1, f(d1), g(d1), h(d1))
		fmt.Printf("%q: %q, %q, %q\n", d2, f(d2), g(d2), h(d2))
	}

	// MISSING: GENERATE ANOTHER BATCH AND RETEST IF NO COLLISION FOUND
}
