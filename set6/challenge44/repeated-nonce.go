package main

import (
	"bytes"
	"fmt"
	"encoding/hex"
	"io/ioutil"
	"math/big"

	"cryptopals/utils"
	"cryptopals/utils/dsa"
)

var file string = "44.txt"

type MessageSig struct {
	dsa.Signature
	message []byte
}

func lineToBigInt(line []byte) *big.Int {
	bites := line[3:]
	bInt := new(big.Int)
	bInt.SetString(string(bites), 10)

	return bInt
}

func extractKey(one, two MessageSig, key dsa.Public) {
	k := dsa.RecoverKFromRepeatedNonce(one.message, two.message, one.Signature, two.Signature, key)
	fmt.Printf("Found k: %s\n", k)
	x := dsa.RecoverKeyFromSigningSecret(one.message, one.Signature, key, k)
	fmt.Printf("Hash of hex string of x: %s\n", hex.EncodeToString(utils.SHA1([]byte(hex.EncodeToString(x.Bytes())))))
}

func main() {

	var key dsa.Public
	key.Q, key.P, key.G = dsa.Q, dsa.P, dsa.G

	key.Y = new(big.Int)
	key.Y.SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)

	data, err := ioutil.ReadFile(file)

	if err != nil {
		panic("Arrgleblarg")
	}

	lines := bytes.Split(data, []byte("\n"))

	db := make(map[string]MessageSig)

	for line :=0; line + 3 < len(lines); line += 4 {
		var m MessageSig
		m.message = lines[line][5:]

		// fmt.Println(string(m.message))

		m.S = lineToBigInt(lines[line+1])
		m.R = lineToBigInt(lines[line+2])
		// line + 3 is Hash of line, not used (we calculate it ourselves)

		match, match_found := db[string(m.R.Bytes())]

		if match_found {
			extractKey(match, m, key)
			return
		}

		db[string(m.R.Bytes())] = m
	}

	fmt.Println("No match found(!!)")
}

