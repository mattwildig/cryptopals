// NOT DONE: ATTACK ON BLOCK CIPHER!

package main

import (
	"bytes"
	"compress/zlib"
	// "encoding/base64"
	"fmt"
	"math"
	"os"

	"cryptopals/utils"
)

var encrypt func([]byte) []byte

func printUsage() {
	fmt.Println("Must specify s (stream) or b (block) for encryption mode (or sb or bn for no encryption")
}

func init() {
	if len(os.Args) != 2 {
		printUsage()
		os.Exit(1)
	}

	if os.Args[1] == "s" {
		encrypt = encryptCtr
	} else if os.Args[1] == "b" {
		encrypt = encryptCbc
	} else if os.Args[1] == "sn" {
		encrypt = encryptNullStream
	} else if os.Args[1] == "bn" {
		encrypt = encryptNullBlock
	} else {
		printUsage()
		os.Exit(1)
	}
}

var TARGET = []byte("TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=")

const FORMAT_STRING = `POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: %d
AnotherHeader: So

%s`

// includes padding '=' character
var BASE64_CHARS = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

func formatRequest(s string) string {
	return fmt.Sprintf(FORMAT_STRING, len(s), s)
}

func compress(s string) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()

	return b.Bytes()
}

func encryptCtr(data []byte) []byte {
	// fmt.Printf("Pre-encrypted lenth: %d ", len(data))
	key := utils.GenKey(16)
	nonce := utils.GenKey(16)

	out := make([]byte, len(data))
	utils.AesCtr(out, data, key, nonce)

	return out
}

func encryptNullStream(data []byte) []byte {
	return data
}

func encryptCbc(data []byte) []byte {
	// fmt.Printf("Pre-encrypted lenth: %d ", len(data))
	key := utils.GenKey(16)
	iv := utils.GenKey(16)

	out := utils.AesCbcEncrypt(utils.PKCS7(data, 16), key, iv)

	return out
}

func encryptNullBlock(data []byte) []byte {
	return utils.PKCS7(data, 16)
}

var oracleCallCount = 0
func oracle(s string) int {
	oracleCallCount ++

	c := compress(formatRequest(s))
	// fmt.Println(c)
	e := encrypt(c)

	return len(e)
}

func printGreen(m string) {
	s := fmt.Sprintf("\x1b[32m%s\x1b[m", m)
	fmt.Println(s)
}

func printRed(m string) {
	s := fmt.Sprintf("\x1b[31m%s\x1b[m", m)
	fmt.Println(s)
}

// func findNextChar(current []byte) byte {
// 	min := math.MaxInt32
// 	minChar := byte(0x00)
// 	for _, c := range(BASE64_CHARS) {
// 		test := string(append(current, c))
// 		count := oracle(test)

// 		if count < min {
// 			min = count
// 			minChar = c
// 		}
// 		fmt.Printf("%s - %s: %d\n", string(c), test, count)
// 	}

// 	return minChar
// }

var randomGunk = utils.GenKey(256)

func findNextCandidates(currentSet [][]byte) [][]byte {
	sessionPrefix := append(randomGunk, []byte("sessionid=")...)
	min := math.MaxInt32
	// minChar := byte(0x00)
	var nextSet [][]byte
	left := len(currentSet)
	count_size := len(fmt.Sprintf("%d", left))
	fmtString := fmt.Sprintf("\r%%0%dd - %%d ", count_size)
	for _, base := range(currentSet) {
		fmt.Printf(fmtString, left, len(nextSet))
		left--
		for _, c := range(BASE64_CHARS) {
			// test := make([]byte, len(base))
			// copy(test, base)
			test := append(base, c)
			dataSize := oracle(string(append(sessionPrefix, test...)))

			if dataSize < min {
				min = dataSize
				copied := make([]byte, len(test))
				copy(copied, test)
				nextSet = append(make([][]byte, 0), copied)
				// fmt.Printf("%q\n", copied)
			} else if dataSize == min {
				copied := make([]byte, len(test))
				copy(copied, test)
				nextSet = append(nextSet, copied)
				// fmt.Printf("%q\n", copied)
			}
			// fmt.Printf("%s - %s: %d\n", string(c), test, count)
		}
	}
	fmt.Print("\r")

	return nextSet
}

func main() {
	candidateSet := make([][]byte, 0)
	candidateSet = append(candidateSet, make([]byte, 0))

	// fixed length guess for now...
	for i := 0; i < 44; i++ {
		candidateSet = findNextCandidates(candidateSet)
		if len(candidateSet) == 1 {
			fmt.Printf("%-47q ", candidateSet[0])
		} else {
			fmt.Printf("(%d candidates) ", len(candidateSet))
		}
		// if len(candidateSet[0]) >= 13 {
		// 	fmt.Println()
		// 	fmt.Println("-----------------")

		// 	last := make([]byte, 0)
		// 	for _, c := range candidateSet {
		// 		fmt.Printf("%q\n", c)
		// 		last = append(last, c[12])
		// 	}
		// 	fmt.Println("-----------------")
		// 	fmt.Printf("%q\n", last)
		// 	return
		// }
		// for i, c := range(candidateSet) {
		// 	fmt.Printf("(%d of %d)%-47q\n", i, len(candidateSet), c)
		// }
		fmt.Printf("(%d oracle calls)\n", oracleCallCount)
	}

	fmt.Println("Final  results:")
	for _, c := range(candidateSet) {
		fmt.Printf("%q: ", c)
		if bytes.Equal(c, TARGET) {
			printGreen("Session key found")
		} else {
			printRed("No match")
		}
	}

	fmt.Printf("Oracle calls: %d\n", oracleCallCount)

}

// func main() {
// 	s := []byte("sessionid=TmV2ZXIgcmV2ZW")
// 	s = append(randomGunk, s...)
// 	next := []byte("CFHPTWXYZacdeinost23/=HTdeinost")

// 	for _, c := range(next) {
// 		data := append(s, c)
// 		request := formatRequest(string(data))
// 		fmt.Printf("%q: %d\n", c, len(compress(request)))
// 	}
// }
