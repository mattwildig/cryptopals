package utils

const MAX_KEYSIZE int = 40

func LikelyKeyLength(text []byte) int {
	min_mean_edit_distance := 9.0
	var likely_key_length int

	for i := 1; i < MAX_KEYSIZE; i++ {
		dist := MeanNormalizedEditDistance(text, i)
		if dist < min_mean_edit_distance {
			min_mean_edit_distance = dist
			likely_key_length = i
		}
	}

	return likely_key_length
}

func Transpose(input []byte, keylen int) [][]byte {
	output := make([][]byte, keylen)

	for i := range output {
		output[i] = make([]byte, 0)
	}

	for i, b := range input {
		output[i%keylen] = append(output[i%keylen], b)
	}

	return output
}
