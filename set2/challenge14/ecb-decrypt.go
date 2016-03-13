package main

import (
	"bytes"
	"cryptopals/utils"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(int64(time.Now().Nanosecond()))
	secretKey = utils.GenKey(16)

	unknownPrefix = utils.GenKey(rand.Intn(128))
}

var secretKey []byte
var unknownPrefix []byte

const targetDataBase64 = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

var targetData = getUnknowData()

func getUnknowData() []byte {
	data, _ := base64.StdEncoding.DecodeString(targetDataBase64)
	return data
}

func encryptionOracle(input []byte) []byte {
	input = append(unknownPrefix, input...)
	input = append(input, targetData...)

	input = utils.PKCS7(input, 16)

	return utils.AesEcbEncrypt(input, secretKey)
}

func main() {
	prefix := []byte("")
	startLen := len(encryptionOracle(prefix))
	blocksize := 0

	for {
		prefix = append(prefix, 'A')
		nextLen := len(encryptionOracle(prefix))

		if startLen != nextLen {
			blocksize = nextLen - startLen
			fmt.Printf("Blocksize: %d\n", blocksize)
			break
		}
	}

	fmt.Printf("Mode: %s\n", utils.DetectEcbOrCbc(encryptionOracle))

	//-----------

	jig := make([]byte, 0)

	prev := encryptionOracle(jig)
	jig = append(jig, 0)
	current := encryptionOracle(jig)

	startBlockIndex := 0

	for startBlockIndex = 0; startBlockIndex < len(targetData); startBlockIndex += blocksize {
		if !bytes.Equal(prev[startBlockIndex:startBlockIndex + blocksize], 
				current[startBlockIndex:startBlockIndex + blocksize]) {
			break
		}
	}

	fmt.Printf("Start block index: %d\n", startBlockIndex)

	for !bytes.Equal(prev[startBlockIndex : startBlockIndex + blocksize],
			current[startBlockIndex : startBlockIndex + blocksize]) {
		jig = append(jig, 0)
		prev, current = current, encryptionOracle(jig)
	}

	jig = make([]byte, (len(jig) -1) % 16)

	fmt.Printf("Jig length: %d\n", len(jig))

	decrypted := make([]byte, len(targetData))

	for knownLen := 0; knownLen < len(targetData); knownLen++ {
		findNextByte(decrypted, knownLen, blocksize, jig, startBlockIndex + 16)
	}

	fmt.Printf("%s\n", decrypted)
}

func findNextByte(known []byte, knownLen, blocksize int, jig []byte, startBlockIndex int) {

	blockIndex := ((knownLen / blocksize) * blocksize) + startBlockIndex

	prefixLen := blocksize - (knownLen % blocksize) - 1
	prefix := make([]byte, prefixLen)

	encryptedBlock := encryptionOracle(append(jig, prefix...))[blockIndex : blockIndex+blocksize]

	prefix = append(prefix, known[:knownLen]...)
	prefix = append(jig, prefix...)

	for i := 0; i <= 256; i++ {
		res := encryptionOracle(append(prefix, byte(i)))[blockIndex : blockIndex+blocksize]

		if bytes.Equal(res, encryptedBlock) {
			known[knownLen] = byte(i)
			return
		}
	}
	panic("Decrypt not found")
}
