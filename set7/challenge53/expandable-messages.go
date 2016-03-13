package main

import (
	// "bytes"
	"fmt"

	"cryptopals/utils"
	"cryptopals/utils/littlehash"
)

// func findCrossCollison(f, g littlehash.HashFunc, size int) ([]byte, []byte, []byte) {
// 	data := make([][]byte, 0)
// 	f_hashes := make([][]byte, 0)
// 	g_hashes := make([][]byte, 0)

// 	for i := 0; i < (1 << uint(size * 8)); i++ {
// 		cand := littlehash.MakeBufferFromInt(i, size)
// 		f_hsh := f(cand)

// 		for i, current := range(g_hashes) {
// 			if bytes.Equal(f_hsh, current) {
// 				return cand, data[i], f_hsh
// 			}
// 		}

// 		g_hsh := g(cand)
// 		for i, current := range(f_hashes) {
// 			if bytes.Equal(g_hsh, current) {
// 				return data[i], cand, g_hsh
// 			}
// 		}

// 		data = append(data, cand)
// 		f_hashes = append(f_hashes, f_hsh)
// 		g_hashes = append(g_hashes, g_hsh)
// 	}
// 	panic("BLERGG")
// }


func makeExpandableMessage(k uint32, initialState []byte) ([][][]byte, []byte) {
	//Assume hash function block size is same as size of initial state
	blockSize := len(initialState)

	pairs := make([][][]byte, 0)

	state := initialState

	// Note: this is the opposite order from the web page, so our pick
	// func will work correctly.
	for i := uint32(0); i < k; i++ {
		dummy_len := 1 << i
		dummy_block := make([]byte, blockSize)

		shortFunc := littlehash.MakeCompressionFunction(state, blockSize)

		dummy_state := state
		for d := 0; d < dummy_len; d++ {
			res := littlehash.SingleBlockAES(dummy_state, dummy_block)
			dummy_state = res[:blockSize]
		}

		longFunc := littlehash.MakeCompressionFunction(dummy_state, blockSize)

		short, long, hsh := littlehash.FindCrossCollison(shortFunc, longFunc, blockSize)
		fmt.Printf("Found expandable component for %d\n", i)
		long_data := make([]byte, dummy_len * blockSize)

		// "filler" bytes, if we want to change from default (0x00)
		// for i := range(long_data) {
		// 	long_data[i] = 0xff
		// }

		long_data = append(long_data, long...)

		pairs = append(pairs, [][]byte{short, long_data})
		state = hsh

	}
	return pairs, state
}

func findCollisionIntoMessage(state []byte, intermediates map[string]uint32) ([]byte, uint32) {
	f := littlehash.MakeCompressionFunction(state, len(state))

	for i := 0; i < (1 << uint(len(state) * 8)); i++ {
		cand := littlehash.MakeBufferFromInt(i, len(state))
		hsh := f(cand)

		ind, ok := intermediates[string(hsh)]
		if ok {
			return cand, ind
		}
	}
	panic("BLERGG")
}

func main() {
	fmt.Println("Starting...")
	k := uint32(16)
	blockSize := 3
	Mlen := (1 << k) * blockSize
	M := utils.GenKey(Mlen)
	mdata := M

	// fmt.Println(littlehash.HashTwoBytes(M))
	intermediateHashes := make(map[string]uint32)

	state := make([]byte, blockSize)
	i := uint32(0)
	for i = 0; len(mdata) > blockSize; i++ {
		res := littlehash.SingleBlockAES(state, mdata[:blockSize])
		state = res[:blockSize]
		mdata = mdata[blockSize:]
		if i > k {
			intermediateHashes[string(state)] = i
		}
	}

	// final block
	mdata = littlehash.PadBlock(mdata, blockSize)
	res := littlehash.SingleBlockAES(state, mdata[:blockSize])
	i++
	intermediateHashes[string(res[:blockSize])] = i

	fmt.Println("Making expandable message...")
	expandableMessage, expandableFinalState := makeExpandableMessage(k, make([]byte, blockSize))

	fmt.Println("Finding collision in message...")
	bridge, index := findCollisionIntoMessage(expandableFinalState, intermediateHashes)

	pre := littlehash.PickChunks(expandableMessage, index - k)

	forged := append(append(pre, bridge...), M[blockSize * int(index) + blockSize:]...)

	fmt.Println(len(M), len(forged))

	f := littlehash.MakeHashFunction(make([]byte, blockSize))
	fmt.Println(f(M))
	fmt.Println(f(forged))

	fmt.Printf("%q\n", M[:64])
	fmt.Printf("%q\n", forged[:64])
}
