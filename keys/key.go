package keys

import "math/rand"

func New(size int) []byte {
	key := make([]byte, size)

	for i := 0; i < size; i++ {
		key[i] = byte(rand.Intn(256))
	}

	return key
}
