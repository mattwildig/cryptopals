package sha1

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func decodeExpected(s string) []byte {
	s = strings.Replace(s, " ", "", -1)

	r, err := hex.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}

	return r
}

func Test_3147_1(t *testing.T) {
	input := []byte("abc")
	expected := decodeExpected("A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D")
	actual := Sum(input)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_3147_2(t *testing.T) {
	inputA := []byte("abcdbcdecdefdefgefghfghighijhi")
	inputB := []byte("jkijkljklmklmnlmnomnopnopq")
	input := append(inputA, inputB...)
	expected := decodeExpected("84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1")
	actual := Sum(input)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_3147_3(t *testing.T) {
	input := []byte("a")
	input = bytes.Repeat(input, 1000000)
	expected := decodeExpected("34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F")
	actual := Sum(input)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_3147_4(t *testing.T) {
	inputA := []byte("01234567012345670123456701234567")
	inputB := []byte("01234567012345670123456701234567")
	input := append(inputA, inputB...)
	input = bytes.Repeat(input, 10)
	expected := decodeExpected("DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52")
	actual := Sum(input)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}
