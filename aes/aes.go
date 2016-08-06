package aes

import (
	"crypto/aes"
	"encoding/binary"
	"errors"

	"cryptopals/xor"
)

func EcbDecrypt(data, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)

	result := make([]byte, len(data))

	buffer := result[:]

	for len(data) > 0 {
		cipher.Decrypt(buffer, data)
		buffer = buffer[cipher.BlockSize():]
		data = data[cipher.BlockSize():]
	}

	return result
}

func EcbEncrypt(data, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)

	result := make([]byte, len(data))

	buffer := result[:]

	for len(data) > 0 {
		cipher.Encrypt(buffer, data)
		buffer = buffer[cipher.BlockSize():]
		data = data[cipher.BlockSize():]
	}

	return result
}

func CbcEncrypt(data, key, iv []byte) []byte {
	cipher, _ := aes.NewCipher(key)

	result := make([]byte, len(data))

	buffer := result[:]
	previous_block := iv

	for len(data) > 0 {
		input, _ := xor.Fixed(data[:cipher.BlockSize()], previous_block)

		cipher.Encrypt(buffer, input)

		previous_block = buffer[:cipher.BlockSize()]

		buffer = buffer[cipher.BlockSize():]
		data = data[cipher.BlockSize():]
	}

	return result
}

func CbcDecrypt(data, key, iv []byte) []byte {
	cipher, _ := aes.NewCipher(key)

	result := make([]byte, 0)

	// buffer := result[:]
	previous_block := iv

	for len(data) > 0 {
		temp := make([]byte, cipher.BlockSize())

		cipher.Decrypt(temp, data)

		// it would be nice if we could XOR directly into the result buffer - see go std lib
		temp, _ = xor.Fixed(temp, previous_block)

		previous_block = data[:cipher.BlockSize()]

		//buffer = buffer[cipher.BlockSize():]
		result = append(result, temp...)
		data = data[cipher.BlockSize():]
	}

	return result
}

// oh Go...
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// May need to change to allow counter/nonce parameters
// Also note different API
func Ctr(dest, data, key, nonce []byte) error {
	if len(dest) < len(data) {
		return errors.New("Dest buffer too small")
	}

	cipher, _ := aes.NewCipher(key)

	counter := uint64(0)

	input := make([]byte, 16)
	copy(input, nonce)

	keystream := make([]byte, 16) // We can't write direct into dest
	                              // as we always need a full block

	for len(data) > 0 {
		binary.LittleEndian.PutUint64(input[8:], counter)

		cipher.Encrypt(keystream, input)
		to_copy := min(len(data), 16)
		xor.FixedBuffer(dest, keystream[:to_copy], data[:to_copy])

		data = data[to_copy:]
		dest = dest[to_copy:]
		counter++
	}
	return nil
}
