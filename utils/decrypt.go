package utils

type DecryptPossibility struct {
	Key     byte
	Decoded []byte
	Score   float64
}

func DecryptSingleByteXOR(cipher []byte) DecryptPossibility {

	current_best := DecryptPossibility{0, nil, 0}

	for key := 0; key <= 255; key++ {
		candidate := SingleByteXOR(cipher, byte(key))
		score := ScoreEnglish(candidate)

		if score > current_best.Score {
			current_best = DecryptPossibility{byte(key), candidate, score}
		}
	}

	return current_best
}

func DecryptRepeatingKeyXOR(input []byte) ([]byte, []byte) {
	key_length := LikelyKeyLength(input)

	blocks := Transpose(input, key_length)

	key := make([]byte, key_length)

	for i, block := range blocks {
		block_result := DecryptSingleByteXOR(block)
		key[i] = block_result.Key
	}

	return RepeatingKeyXOR(input, key), key
}

func DecryptFixedNonceCtr(inputs [][]byte) [][]byte {
	shortest := 99999

	for _, c := range inputs {
		if len(c) < shortest {
			shortest = len(c)
		}
	}

	transposed := make([][]byte, shortest)
	for i := range transposed {
		transposed[i] = make([]byte, len(inputs))
	}

	for i, t := range inputs {
		for c := 0; c < shortest; c++ {
			transposed[c][i] = t[c]
		}
	}

	key := make([]byte, shortest)

	for i, chars := range transposed {
		sol := DecryptSingleByteXOR(chars)
		key[i] = sol.Key
	}

	results := make([][]byte, len(inputs))

	for i, e := range inputs {
		res := make([]byte, len(key))
		copy(res, e)
		err := FixedXORBuffer(res, e[:len(key)], key)
		if err != nil {
			results[i] = []byte(err.Error())
		} else {
			results[i] = res
		}
	}
	return results
}
