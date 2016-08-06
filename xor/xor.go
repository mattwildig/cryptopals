package xor

import "errors"

func Fixed(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("Args to FixedXOR must be the same size")
	}

	result := make([]byte, len(b1))

	for i, v := range b1 {
		result[i] = v ^ b2[i]
	}

	return result, nil
}

func FixedBuffer(dest, b1, b2 []byte) error {
	if len(b1) != len(b2) {
		return errors.New("Args to FixedXOR must be the same size")
	}

	if len(dest) < len(b1) {
		return errors.New("Dest buffer too small")
	}

	for i, v := range b1 {
		dest[i] = v ^ b2[i]
	}

	return nil
}

func SingleByte(input []byte, key byte) []byte {

	result := make([]byte, len(input))

	for i, v := range input {
		result[i] = key ^ v
	}

	return result
}

func RepeatingKey(data, key []byte) []byte {
	output := make([]byte, len(data))

	for index, char := range data {
		output[index] = char ^ key[index%len(key)]
	}

	return output
}
