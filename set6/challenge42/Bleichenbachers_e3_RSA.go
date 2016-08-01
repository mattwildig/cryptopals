package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"math/big"

	"cryptopals/utils"
)

var ASNPrefix = []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
var asnSwitch string

const rsaBitLength = 2048
var rsaByteLength int


func init() {
	flag.StringVar(&asnSwitch, "a", "s", "how to create asn: s: simple, p: processor")
	flag.Parse()

	rsaByteLength = rsaBitLength / 8
}

func encodeASN(hash []byte) []byte {
	switch asnSwitch {
	case "s":
		return append(ASNPrefix, hash...)
	case "p":
		return createASN(hash)
	default:
		panic("Invalid ASN switch")
	}
}

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

	if ! bytes.Equal(data[pos:pos + len(ASNPrefix)], ASNPrefix) {
		return nil, errors.New("Incorrect ASN.1 bytes")
	}

	pos += len(ASNPrefix)

	// Just SHA1 for now (20 bytes)
	return data[pos:pos +20], nil
}

// Returns rsaByteLength byte (rsaBitLength bit) formatted signature block
func create_block(digest []byte) ([]byte, error) {
	if len(digest) != 20 {
		return nil, errors.New("Digest should be 20 bytes (SHA1 only)")
	}

	digest = encodeASN(digest)

	block := make([]byte, rsaByteLength)

	// PKCS1v1.5 padding...
	p := 0
	block[p] = 0x00; p++
	block[p] = 0x01; p++
	// 0xff bytes (rsaByteLength - 2(prefix bytes) - 1(zero suffix) - len(ASN + hash))
	// = rsaByteLength - 3 - len(digest)
	for i := 0; i < rsaByteLength - 3 - len(digest); i++ {
		block[p] = 0xff; p++
	}
	block[p] = 0x00; p++

	copy(block[p:], digest)

	return block, nil
}

func verify(rsa utils.RSA, signature, message []byte) bool {
	// verification is encryption
	block := rsa.EncryptBytes(signature)

	//lpad block to 128 bytes
	zeros := rsaByteLength - len(block)

	if zeros < 0 {
		panic("Padding shouldn't be negative")
	}

	block = append(make([]byte, zeros), block...)
	fmt.Printf("After encryption (when verifying):\n%x\n", block)

	digest, err := parse_data(block)

	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	our_digest := utils.SHA1(message)

	if bytes.Equal(digest, our_digest) {
		return true
	}
	fmt.Printf("Digests don't match:\nExpected:\t%x\nActual:\t\t%x\n", our_digest, digest)
	return false
}

func make_forgery(message []byte) []byte {
	digest := utils.SHA1(message)
	block := make([]byte, rsaByteLength)
	p := 0

	block[p] = 0x00; p++
	block[p] = 0x01; p++
	// rfc3447 says there should be at least 8 0xff bytes,
	// so we'll have that many
	for i:= 0; i < 8; i ++ {
		block[p] = 0xff; p++
	}
	block[p] = 0x00; p++

	digest = encodeASN(digest)

	copy(block[p:p+len(digest)], digest)

	p += len(digest)

	fmt.Printf("Message to forge hashed and formatted:\n%x\n", block)

	block_as_int := new(big.Int)
	block_as_int.SetBytes(block)

	forged_sig := utils.CubeRoot(block_as_int).Bytes()

	return forged_sig
}

func main() {
	message := []byte("Hi, everybody")

	fmt.Printf("Original message: %s\n", string(message))

	digest := utils.SHA1(message)
	block, err := create_block(digest)

	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Hashed and formatted:\n%x\n", block)

	fmt.Print("Creating RSA key...")
	key := utils.CreateRSA(rsaBitLength, 3)
	fmt.Println("done")

	// Signing is decrypt
	signature := key.DecryptBytes(block)

	fmt.Printf("Signed block:\n%x\n", signature)

	// mimic different user who doesn't have decryption key
	key.D = nil

	verified := verify(key, signature, message)

	fmt.Printf("Original signature verifies: %t\n", verified)
	fmt.Println()

	message_to_forge := []byte("hi Mum")
	fmt.Printf("Message to forge: %s\n", string(message_to_forge))

	forgery := make_forgery(message_to_forge)

	fmt.Printf("Forged signature:\n%x\n", forgery)

	verified = verify(key, forgery, message_to_forge)

	fmt.Printf("Forged signature verifies: %t\n", verified)
}
