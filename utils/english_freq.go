package utils

import "math"

var EnglishLetterFrequency []float64 = initEnglishLetterFrequency()

func initEnglishLetterFrequency() []float64 {
	e := make([]float64, 256)
	e[' '] = 18.28846265
	e['A'] = 6.53216702
	e['B'] = 1.25888074
	e['C'] = 2.23367596
	e['D'] = 3.28292310
	e['E'] = 10.26665037
	e['F'] = 1.98306716
	e['G'] = 1.62490441
	e['H'] = 4.97856396
	e['I'] = 5.66844326
	e['J'] = 0.09752181
	e['K'] = 0.56096272
	e['L'] = 3.31754796
	e['M'] = 2.02656783
	e['N'] = 5.71201113
	e['O'] = 6.15957725
	e['P'] = 1.50432428
	e['Q'] = 0.08367550
	e['R'] = 4.98790855
	e['S'] = 5.31700534
	e['T'] = 7.51699827
	e['U'] = 2.27579536
	e['V'] = 0.79611644
	e['W'] = 1.70389377
	e['X'] = 0.14092016
	e['Y'] = 1.42766662
	e['Z'] = 0.05128469

	return e
}

func DotProduct(a, b []float64) float64 {
	sum := float64(0)
	for i, v := range a {
		sum += b[i] * v
	}

	return sum
}

func VectorAbs(vec []float64) float64 {
	sum := float64(0)
	for _, v := range vec {
		sum += v * v
	}
	return math.Sqrt(sum)
}

func CosineSimilarity(a, b []float64) float64 {
	dot := DotProduct(a, b)
	abs := VectorAbs(a) * VectorAbs(b)

	return dot / abs
}

func histogram(input []byte) []float64 {
	hist := make([]float64, 256)

	for _, c := range input {

		if c > 96 && c < 123 {
			c -= 32 // only lower case
		}

		hist[c]++
	}

	return hist
}

func ScoreEnglish(v []byte) float64 {
	return CosineSimilarity(histogram(v), EnglishLetterFrequency)
}
