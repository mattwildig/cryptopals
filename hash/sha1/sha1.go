package sha1

import (
	"encoding/binary"
)

const (
	H0 uint32 = 0x67452301
	H1 uint32 = 0xEFCDAB89
	H2 uint32 = 0x98BADCFE
	H3 uint32 = 0x10325476
	H4 uint32 = 0xC3D2E1F0
)

type SHA1_t struct {
	H [5]uint32
	Data []byte
}

func leftrotate(x uint32, shift uint) uint32 {
	return (x << shift) | (x >> (32 - shift))
}

func Bit_padding(message_len int) []byte {
	message_len_bits := uint64(message_len * 8)

	message_len ++ // for 0x80 byte
	zeros := 0

	if message_len % 64  <= 56 {
		zeros = 64 - (message_len % 64)
	} else {
		zeros = 64 + (64 - (message_len % 64))
	}

	padding := make([]byte, 1 + zeros)
	padding[0] = 0x80
	binary.BigEndian.PutUint64(padding[len(padding) - 8:], message_len_bits)

	return padding
}

func pad(data []byte) []byte {
	return append(data, Bit_padding(len(data))...)
}

func (s * SHA1_t) process_chunk(chunk []byte) {
	var words [80]uint32

	for i := 0; i < 16; i++ {
		words[i] = binary.BigEndian.Uint32(chunk[i * 4: (i + 1) * 4])
	}

	for i := 16; i < 80; i++ {
		words[i] = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]
		words[i] = leftrotate(words[i], 1)
	}

	a, b, c, d, e := s.H[0], s.H[1], s.H[2], s.H[3], s.H[4]
	var f, k, temp uint32

	for i := 0; i < 80; i++ {
		if i < 20 {
			f = (b & c) | ((^b) & d)
			k = 0x5A827999
		} else if i < 40 {
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		} else if i < 60 {
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		} else if i < 80 {
			f = b ^ c ^ d
			k = 0xCA62C1D6
		}

		temp = leftrotate(a, 5) + f + e + k + words[i]

		e = d
		d = c
		c = leftrotate(b, 30)
		b = a
		a = temp
	}

	s.H[0] = s.H[0] + a
	s.H[1] = s.H[1] + b
	s.H[2] = s.H[2] + c
	s.H[3] = s.H[3] + d
	s.H[4] = s.H[4] + e

}

func (s *SHA1_t) Process() {
	for len(s.Data) > 0 {
		s.process_chunk(s.Data[:64])
		s.Data = s.Data[64:]
	}
}

func (s *SHA1_t) Finalise() []byte {
	result := make([]byte, 20)
	for i := 0; i < 5; i++ {
		binary.BigEndian.PutUint32(result[i * 4:(i + 1) * 4], s.H[i])
	}

	return result
}

func (s *SHA1_t) Init(data []byte) {
	s.H[0] = H0
	s.H[1] = H1
	s.H[2] = H2
	s.H[3] = H3
	s.H[4] = H4

	s.Data = data
}

func Sum(data []byte) []byte {
	data = pad(data)
	s := SHA1_t{}
	s.Init(data)
	s.Process()

	return s.Finalise()
}

func Sign(key, data []byte) []byte {
	return Sum(append(key, data...))
}
