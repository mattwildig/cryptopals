// An example of ASN.1 encoding using a processor. Normally this isn't done
// this way, the ASN.1 prefix is calculated in advance and simply added to
// the digest (with a check to see the data is the right length). See the Go
// RSA package source for an example.

package main

import (
	"encoding/asn1"
)

// This is the identifier for SHA1, taken from the RFC. Other hash functions
// have their own identifiers.
var SHA1Oid asn1.ObjectIdentifier = []int{1, 3, 14, 3, 2, 26}

// '5' is the tag for a ASN.1 Null value. There doesn't seem to be any other
// way to create a Null other than like this.
var NullAsn asn1.RawValue = asn1.RawValue{Tag: 5}

type AlgorithmIdentifier struct {
	Id     asn1.ObjectIdentifier
	Params asn1.RawValue // This is Null for SHA1 (and all other hash functions).
}

var SHA1AlgorithmIdentifier = AlgorithmIdentifier{SHA1Oid, NullAsn}

type DigestInfo struct {
	DigestAlgorithm AlgorithmIdentifier
	Digest          []byte
}

func createASN(digest []byte) []byte {

	digestInfo := DigestInfo{SHA1AlgorithmIdentifier, digest}

	asn, err := asn1.Marshal(digestInfo)

	if err != nil {
		panic("Error creating ASN")
	}
	return asn
}
