package utils

import "errors"

// import "fmt"

func PKCS7(data []byte, block_size int) []byte {
	padding_size := block_size - (len(data) % block_size)

	padding := make([]byte, padding_size)

	for i := range padding {
		padding[i] = byte(padding_size)
	}

	return append(data, padding...)
}

func CheckAndStripPKCS7(padded []byte) ([]byte, error) {
	// check input is multiple of block size?
	paddedCount := padded[len(padded)-1]

	// padding of 0 is invalid and will cause problems for your padding oracle
	// if you allow it!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	if paddedCount > byte(len(padded)) || paddedCount == 0 {
		return nil, errors.New("Invalid padding")
	}

	paddingStart := len(padded) - int(paddedCount)

	for i := paddingStart; i < len(padded); i++ {
		if padded[i] != paddedCount {
			return nil, errors.New("Invalid padding")
		}
	}
	return padded[:paddingStart], nil
}
