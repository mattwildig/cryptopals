package littlehash

import (
	"bytes"
	"encoding/binary"

	"crypto/aes"
	"fmt"
)

type CompressionFunc func([]byte, []byte) []byte
type HashFunc func([]byte) []byte // also compression func with state

func PadBlock(data []byte, length int) []byte {
	if len(data) > length {
		panic("Data too long to be padded")
	}
	padded := make([]byte, length)
	copy(padded, data)
	return padded
}

//(copied)
const AES_BLOCK_SIZE = 16

// key is state
func SingleBlockAES(key, data []byte) []byte {
	key = PadBlock(key, AES_BLOCK_SIZE)
	data = PadBlock(data, AES_BLOCK_SIZE)
	result := make([]byte, AES_BLOCK_SIZE)

	cipher, _ := aes.NewCipher(key)
	cipher.Encrypt(result, data)

	return result
}

var HashTwoBytes = MakeHashFunction(make([]byte, 2))
var HashThreeBytes = MakeHashFunction(make([]byte, 3))

func MakeHashFunction(startState []byte) func([]byte) []byte {

	length := len(startState)

	return func(data []byte)[]byte {
		state := startState

		for len(data) > length {
			res := SingleBlockAES(state, data[:length])
			state = res[:length]
			data = data[length:]
		}

		// final block
		data = PadBlock(data, length)
		res := SingleBlockAES(state, data[:length])
		return res[:length]
	}

}

func MakeBufferFromInt(i, size int) []byte {
	res := make([]byte, 8)
	binary.BigEndian.PutUint64(res, uint64(i))

	return res[8-size:]
}

// Note: Careful how bits in puck and entries in pairs/result
// line up. Low bits (i.e. conceptually on the RHS correspond to
// early entries (i.e.  on the LHS))
func PickChunks(pairs [][][]byte, pick uint32) []byte {
	result := make([]byte, 0)

	for i := uint32(0); i < uint32(len(pairs)); i++ {
		chosen := ((1 << i) & pick) >> i
		// result[i] = pairs[i][chosen]
		result = append(result, pairs[i][chosen]...)
	}

	return result
}

// create a reusable compression func so we can reuse it lots
func MakeCompressionFunction(state []byte, length int) HashFunc {

	state = PadBlock(state, AES_BLOCK_SIZE)

	// use AES directly (not through our wrapper)
	cipher, _ := aes.NewCipher(state)

	return func(data []byte) []byte {
		if len(data) != length {
			panic(fmt.Sprintf("Incorrect data length for hash function: %d (exected %d)", len(data), length))
		}
		data = PadBlock(data, AES_BLOCK_SIZE)
		result := make([]byte, AES_BLOCK_SIZE)
		cipher.Encrypt(result, data)

		return result[:length]
	}
}

func FindCrossCollison(f, g HashFunc, size int) ([]byte, []byte, []byte) {
	data := make([][]byte, 0)
	f_hashes := make([][]byte, 0)
	g_hashes := make([][]byte, 0)

	for i := 0; i < (1 << uint(size * 8)); i++ {
		cand := MakeBufferFromInt(i, size)
		f_hsh := f(cand)

		for i, current := range(g_hashes) {
			if bytes.Equal(f_hsh, current) {
				return cand, data[i], f_hsh
			}
		}

		g_hsh := g(cand)
		for i, current := range(f_hashes) {
			if bytes.Equal(g_hsh, current) {
				return data[i], cand, g_hsh
			}
		}

		data = append(data, cand)
		f_hashes = append(f_hashes, f_hsh)
		g_hashes = append(g_hashes, g_hsh)
	}
	panic("BLERGG")
}
