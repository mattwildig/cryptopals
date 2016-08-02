// Bleichenbachers e = 3 RSA attack.
//
// With RSA parameter e = 3 and a broken PKCS1v15 parser that doesn't correctly
// check that the data is right justified a forged signature can be created by
// simply finding the cube root of an appropriately prepared block.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"math/big"

	"cryptopals/bigx"
	"cryptopals/hash/sha1"
	"cryptopals/rsa"
)

// The bytes of the ASN.1 prefix for SHA1. Used when verifying and when using
// simple method of encoding the ASN.1.
var ASNPrefix = []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}

// Holds the -a command line option.
var asnSwitch string

// Size of key to use.
const rsaBitLength = 2048

var rsaByteLength int

func init() {
	flag.StringVar(&asnSwitch, "a", "s", "how to create asn: s: simple, p: processor")
	flag.Parse()

	rsaByteLength = rsaBitLength / 8
}

// Convert the raw digest bytes into the ASN.1 encoded data structure,
// using the method specified by the -a option. The end result is the
// same whichever method is used.
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
// (this is the broken version, doesn't ckeck if digest is right justified).
func parse_data(data []byte) ([]byte, error) {

	if data[0] != 0x00 {
		return nil, errors.New("First byte must be 0x00")
	}

	if data[1] != 0x01 {
		return nil, errors.New("Second byte must be 0x01")
	}

	pos := 2

	for data[pos] == 0xff {
		pos++
	}

	if data[pos] != 0x00 {
		return nil, errors.New("First byte after 0xff block must be 0x00")
	}

	pos++

	if !bytes.Equal(data[pos:pos+len(ASNPrefix)], ASNPrefix) {
		return nil, errors.New("Incorrect ASN.1 bytes")
	}

	pos += len(ASNPrefix)

	// Just SHA1 for now (20 bytes).
	return data[pos : pos+20], nil
}

// Returns rsaByteLength byte (rsaBitLength bit) formatted signature block.
func create_block(digest []byte) ([]byte, error) {
	if len(digest) != 20 {
		return nil, errors.New("Digest should be 20 bytes (SHA1 only)")
	}

	digest = encodeASN(digest)

	buf := bytes.NewBuffer(make([]byte, 0, rsaByteLength))

	// PKCS1v1.5 padding...
	buf.Write([]byte{0x00, 0x01})
	// 0xff bytes (rsaByteLength - 2(prefix bytes) - 1(zero suffix) - len(ASN + hash))
	// = rsaByteLength - 3 - len(digest)
	for i := 0; i < rsaByteLength-3-len(digest); i++ {
		buf.WriteByte(0xff)
	}
	buf.WriteByte(0x00)

	buf.Write(digest)

	return buf.Bytes(), nil
}

// Verifies that the signature is valid for the message and key, using the
// (broken!) parse_data() function.
func verify(rsa rsa.RSA, signature, message []byte) bool {
	// Verification is RSA encryption.
	block := rsa.EncryptBytes(signature)

	// Lpad block to rsaByteLength bytes (should be just one byte).
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

	our_digest := sha1.Sum(message)

	if bytes.Equal(digest, our_digest) {
		return true
	}
	fmt.Printf("Digests don't match:\nExpected:\t%x\nActual:\t\t%x\n", our_digest, digest)
	return false
}

// Creates a forged signature for the message, relying on the broken parsing.
func make_forgery(message []byte) []byte {
	digest := sha1.Sum(message)

	// Create a suitably sized []byte.
	block := make([]byte, rsaByteLength)

	// Create a buffer using the block, but with a zero length slice,
	// so that we will write into block.
	buf := bytes.NewBuffer(block[:0])

	buf.Write([]byte{0x00, 0x01})

	// RFC3447 says there should be at least 8 0xff bytes,
	// so we'll have exactly that many.
	for i := 0; i < 8; i++ {
		buf.WriteByte(0xff)
	}
	buf.WriteByte(0x00)

	digest = encodeASN(digest)

	buf.Write(digest)

	// Now use block, which has been written into, but still has correct
	// number of trailing zeros.
	fmt.Printf("Message to forge hashed and formatted:\n%x\n", block)

	block_as_int := new(big.Int)
	block_as_int.SetBytes(block)

	forged_sig := bigx.CubeRoot(block_as_int).Bytes()

	return forged_sig
}

func main() {
	message := []byte("Hi, everybody")

	fmt.Printf("Original message: %s\n", string(message))

	digest := sha1.Sum(message)
	block, err := create_block(digest)

	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Hashed and formatted:\n%x\n", block)

	fmt.Print("Creating RSA key...")
	key := rsa.CreateRSA(rsaBitLength, 3)
	fmt.Println("done")

	// Signing is RSA decryption.
	signature := key.DecryptBytes(block)

	fmt.Printf("Signed block:\n%x\n", signature)

	// Mimic different user who doesn't have decryption key.
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
