package utils

import "bytes"

func DetectEcbOrCbc(encryptor func([]byte) []byte) string {
	data := make([]byte, 128)

	result := encryptor(data)

	for len(result) > 31 {
		if bytes.Equal(result[:16], result[16:32]) {
			return "ecb"
		}
		result = result[32:]
	}

	return "cbc"
}
