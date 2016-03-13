package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"cryptopals/utils"
)

// Just mock this part for now
var ASN = []byte("ASN")

// Returns the digest from the formatted data block
// (this is the broken version, doesn't ckeck if digest is right justified)
func parse_data(data []byte) ([]byte, error) {

	if data[0] != 0x00 {
		return nil, errors.New("First byte must be 0x00")
	}

	if data[1] != 0x01 {
		return nil, errors.New("Second byte must be 0x01")
	}

	pos := 2

	for data[pos] == 0xff {
		pos ++
	}

	if data[pos] != 0x00 {
		return nil, errors.New("First byte after 0xff block must be 0x00")
	}

	pos ++

	if ! bytes.Equal(data[pos:pos + 3], ASN) {
		return nil, errors.New("ASN bytes must be \"ASN\"")
	}

	pos += 3

	// Just SHA1 for now (20 bytes)
	return data[pos:pos +20], nil
}

// Returns 128 byte (1024 bit) formatted signature block
func create_block(digest []byte) ([]byte, error) {
	if len(digest) != 20 {
		return nil, errors.New("Digest should be 20 bytes (SHA1 only)")
	}

	block := make([]byte, 128)
	block[0] = 0x00
	block[1] = 0x01
	// 102 0xff bytes (128 - 20(hash) - 2(prefix bytes) - 1(zero suffix) - 3(ASN))
	for i := 2; i < 104; i++ {
		block[i] = 0xff
	}
	block[104] = 0x00
	copy(block[105:108], ASN)
	copy(block[108:], digest)

	return block, nil
}

func verify(rsa utils.RSA, signature, message []byte) bool {
	// verification is encryption
	block := rsa.EncryptBytes(signature)

	fmt.Printf("After cubing back agian: %v\n", block)

	//lpad block to 128 bytes
	zeros := 128 - len(block)

	if zeros < 0 {
		panic("Oops, padding shouldn't be negative")
	}

	block = append(make([]byte, zeros), block...)

	digest, err := parse_data(block)

	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	our_digest := utils.SHA1(message)

	if bytes.Equal(digest, our_digest) {
		return true
	}

	return false
}

func make_forgery(message []byte) []byte {
	digest := utils.SHA1(message)
	block := make([]byte, 128)

	block[0] = 0x00
	block[1] = 0x01
	// rfc3447 says there should be at least 8 0xff bytes,
	// so we'll have that many
	for i:= 2; i < 10; i ++ {
		block[i] = 0xff
	}
	block[10] = 0x00
	copy(block[11:14], ASN)

	copy(block[14:34], digest)

	fmt.Printf("Before cuberoot: %v\n", block)

	block_as_int := new(big.Int)
	block_as_int.SetBytes(block)

	forged_sig := utils.CubeRoot(block_as_int).Bytes()

	return forged_sig	
}

func main() {
	message := []byte("Hi, everybody")

	digest := utils.SHA1(message)
	block, err := create_block(digest)

	if err != nil {
		panic(err.Error())
	}

	key := utils.CreateRSA(1024, 3)
	// Signing is decrypt
	signature := key.DecryptBytes(block)

	// mimic different user who doesn't have decryption key
	key.D = nil

	verified := verify(key, signature, message)

	fmt.Println(verified)

	message_to_forge := []byte("hi Mum")
	forgery := make_forgery(message_to_forge)

	verified = verify(key, forgery, message_to_forge)

	fmt.Println(verified)
}
