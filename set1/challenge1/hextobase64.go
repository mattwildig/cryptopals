package main

import "fmt"
import "encoding/hex"
import "encoding/base64"

func main() {
	hex_string := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	expected_string := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	decoded_string, _ := hex.DecodeString(hex_string)
	converted_string := base64.StdEncoding.EncodeToString(decoded_string)

	fmt.Printf("Strings match: %t\n", expected_string == converted_string)
}
