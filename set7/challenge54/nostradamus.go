package main

import (
	"bytes"
	"math/rand"
	"fmt"

	"cryptopals/utils"
	"cryptopals/utils/littlehash"
	"cryptopals/utils/text"
)

func containsState(states [][][]byte, state []byte) bool {
	for _, s := range(states) {
		if s == nil {
			return false
		}
		if bytes.Equal(s[0], state) {
			return true
		}
	}

	return false
}

func initDiamond(k, blockSize int) [][][]byte {
	total := 1 << uint(k) // 2 ** k
	states := make([][][]byte, total)

	for i := 0; i < total; i++ {
		states[i] = make([][]byte, 2)

		state := utils.GenKey(blockSize)
		for containsState(states, state) {
			state = utils.GenKey(blockSize)
		}

		states[i][0] = state
	}

	return states
}

func collidePairs(in [][][]byte) [][][]byte {
	result :=  make([][][]byte, len(in) / 2)
	hashSize := len(in[0])

	for i := 0; i < len(in); i += 2 {
		f := littlehash.MakeCompressionFunction(in[i][0], hashSize)
		g := littlehash.MakeCompressionFunction(in[i + 1][0], hashSize)

		f_data, g_data, new_state := littlehash.FindCrossCollison(f, g,  hashSize)

		// next data blocks for the two states
		in[i][1] = f_data
		in[i + 1][1] = g_data

		// new state (in position 1/2 for both current states)
		result[i/2] = make([][]byte, 2)
		result[i/2][0] = new_state
	}

	return result
}

func constructSuffix(diamond [][][][]byte, index int) []byte {
	result := make([]byte, 0)

	for i := 0; i < len(diamond); i++ {
		result = append(result, diamond[i][index][1]...)
		index /= 2
	}

	return result
}

func joinToDiamond(diamond [][][][]byte, hashFunc littlehash.HashFunc, block_size int) ([]byte, int) {
	for i := 0; i < 1 << uint(block_size * 8); i++ {
		block := littlehash.MakeBufferFromInt(i, block_size)
		new_state := hashFunc(block)

		for index, entry := range(diamond[0]) {
			if bytes.Equal(new_state, entry[0]) {
				return block, index
			}
		}
	}
	text.PrintRed("Unable to find match in diamond")
	panic("BLERGG")
}

func main() {
	block_size := 2

	text.PrintGreen("Starting")
	fmt.Println("Initializing diamond...")

	k := 8
	diamond := make([][][][]byte, k+1)
	diamond[0] = initDiamond(k, block_size)

	for i := 0; i < k; i++ {
		diamond[i + 1] = collidePairs(diamond[i])
	}

	// note: no length strengthening yet
	prediction := diamond[k][0][0]

	fmt.Println("Done")

	text.PrintGreen("Checking...")
	final_hashes  := make([][]byte, 0)
	for i := 0; i < 1 << uint(k); i ++ {
		suffix := constructSuffix(diamond, i)
		state := diamond[0][i][0]
		hashFunc := littlehash.MakeHashFunction(state)
		hash := hashFunc(suffix)
		final_hashes = append(final_hashes, hash)
		// fmt.Printf("%d: %q, -- %q\n", i, suffix, hash)
	}

	for _, v := range(final_hashes) {
		if ! bytes.Equal(v, final_hashes[0]) {
			text.PrintRed("Hashes not equal")
			return
		}
	}
	text.PrintGreen("All hashes Equal")

	fmt.Println()
	fmt.Printf("Prediction: %q\n", prediction)

	result := rand.Intn(100)

	// need padding for length checks
	// also need to check this is multiple of block length
	message := []byte(fmt.Sprintf("The result will be %d ", result))

	last_state := littlehash.HashTwoBytes(message)
	hashFunc := littlehash.MakeHashFunction(last_state)
	join, index := joinToDiamond(diamond, hashFunc, block_size)

	message = append(message, join...)
	message = append(message, constructSuffix(diamond, index)...)
	hash := littlehash.HashTwoBytes(message)

	fmt.Printf("%q\n", message)
	fmt.Printf("Hash: %q\n", hash)

	if bytes.Equal(hash, prediction) {
		text.PrintGreen("Hash matched prediction")
	} else {
		text.PrintRed("Hash doesn’t match prediction")
	}
}
