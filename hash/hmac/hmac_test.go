package hmac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func decode(s string) []byte {
	r, err := hex.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}

	return r
}

func Test_2202_SHA1_1(t *testing.T) {
	key := decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")
	expected := decode("b617318655057264e28bc0b6fb378c8ef146be00")

	actual := HMAC_SHA1(key, data)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_2202_SHA1_2(t *testing.T) {
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	expected := decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")

	actual := HMAC_SHA1(key, data)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_2202_SHA1_3(t *testing.T) {
	key := decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	data := make([]byte, 50)
	for i := range(data) {
		data[i] = 0xdd
	}
	expected := decode("125d7342b9ac11cd91a39af48aa17b4f63f175d3")

	actual := HMAC_SHA1(key, data)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_2202_SHA1_4(t *testing.T) {
	key := decode("0102030405060708090a0b0c0d0e0f10111213141516171819")
	data := make([]byte, 50)
	for i := range(data) {
		data[i] = 0xcd
	}
	expected := decode("4c9007f4026250c6bc8414f9bf50c86c2d7235da")

	actual := HMAC_SHA1(key, data)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_2202_SHA1_5(t *testing.T) {
	key := decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
	data := []byte("Test With Truncation")

	expected := decode("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")

	actual := HMAC_SHA1(key, data)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_2202_SHA1_6(t *testing.T) {
	key := make([]byte, 80)
	for i := range(key) {
		key[i] = 0xaa
	}
	data := []byte("Test Using Larger Than Block-Size Key - Hash Key First")

	expected := decode("aa4ae5e15272d00e95705637ce8a3b55ed402112")

	actual := HMAC_SHA1(key, data)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}

func Test_2202_SHA1_7(t *testing.T) {
	key := make([]byte, 80)
	for i := range(key) {
		key[i] = 0xaa
	}
	data := []byte("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")

	expected := decode("e8e99d0f45237d786d6bbaa7965c7808bbff1a91")

	actual := HMAC_SHA1(key, data)

	if !bytes.Equal(expected, actual) {
		t.Fail()
	}
}
