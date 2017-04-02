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

// 6234 test 5 deals with input that's not multiple of 8 bits

func Test_6234_6(t *testing.T) {
	input := []byte("\x5e")

	expected := decodeExpected("5E6F80A34A9798CAFC6A5DB96CC57BA4C4DB59C2")
	actual := Sum(input)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

// 6234 test 7 deals with input that's not multiple of 8 bits

func Test_6234_8(t *testing.T) {
	input := []byte("\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46")

	expected := decodeExpected("82ABFF6605DBE1C17DEF12A394FA22A82B544A35")
	actual := Sum(input)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

// 6234 test 9 deals with input that's not multiple of 8 bits

func Test_6234_10(t *testing.T) {
	inputString := "\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f" +
	"\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15" +
	"\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92" +
	"\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f" +
	"\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04" +
	"\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca" +
	"\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b" +
	"\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60" +
	"\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80" +
	"\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27" +
	"\xcd\xbb\xfb"

	input := []byte(inputString)

	expected := decodeExpected("CB0082C8F197D260991BA6A460E76E202BAD27B3")
	actual := Sum(input)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}
