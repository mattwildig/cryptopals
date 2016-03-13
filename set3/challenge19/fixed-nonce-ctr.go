package main

import (
	"encoding/base64"
	"cryptopals/utils"
	"fmt"
)

var key = utils.GenKey(16)
var nonce = make([]byte, 8)

var strings = [...]string{
	"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
}

func main() {
	encrypts := make([][]byte, len(strings))
	shortest := 9999
	for i, s := range strings {
		d, _ := base64.StdEncoding.DecodeString(s)
		dest := make([]byte, len(d))
		e := utils.AesCtr(dest, d, key, nonce)
		if e != nil {
			panic("AesCtr didn't work!")
		}

		if len(d) < shortest {
			shortest = len(d)
		}

		encrypts[i] = dest
	}

	results := utils.DecryptFixedNonceCtr(encrypts)

	for _, decrypt := range results {
		fmt.Println(string(decrypt))
	}

	// transposed := make([][]byte, shortest)
	// for i := range transposed {
	// 	transposed[i] = make([]byte, len(strings))
	// }

	// for i, t := range encrypts {
	// 	for c := 0; c < shortest; c++ {
	// 		transposed[c][i] = t[c]
	// 	}
	// }

	// key := make([]byte, shortest)

	// for i, chars := range transposed {
	// 	sol := utils.DecryptSingleByteXOR(chars)
	// 	key[i] = sol.Key
	// }

	// fmt.Printf("%q\n", key)

	// for _, e := range encrypts {
	// 	res := make([]byte, len(e))
	// 	copy(res, e)
	// 	err := utils.FixedXORBuffer(res, e[:len(key)], key)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	} else {
	// 		fmt.Printf("%q\n", res)
	// 	}
	// }

	// fmt.Println()

	// key = []byte("\xb0\x8f\x85T$F3*\xa8_6 \b\x1a.\xc6?Բ\xa7\x99J\xdc\x2d\x6c3\xa9p\x89\x8as\xbb\x8e%\xbe>Sz")

	// for _, e := range encrypts {

	// 	lim := min(len(e), len(key))


	// 	err := utils.FixedXORBuffer(e, e[:lim], key[:lim])
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	} else {
	// 		fmt.Printf("%q\n", e)
	// 	}
	// }
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
