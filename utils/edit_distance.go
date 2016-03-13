package utils

func PopCount(b byte) int {
	count := byte(0)
	var i byte
	for i = 0; i < 8; i++ {
		count += (b >> i) & 1
	}
	return int(count)
}

func EditDistance(one, two []byte) int {
	count := 0

	// assume one and two are the same length because error handling is a pain
	for i, b := range one {
		count += PopCount(b ^ two[i])
	}

	return count
}

func NormalizedEditDistance(one, two []byte) float64 {
	return float64(EditDistance(one, two)) / float64(len(one))
}

func MeanNormalizedEditDistance(text []byte, keylen int) float64 {
	chunksize := keylen * 2
	totalEditDistance := 0.0
	numChunks := 0

	for i := 0; i+chunksize < len(text); i += chunksize {
		totalEditDistance += NormalizedEditDistance(text[i:(i+keylen)], text[(i+keylen):(i+chunksize)])
		numChunks++
	}

	return totalEditDistance / float64(numChunks)
}
