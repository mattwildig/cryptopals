package utils

import (
	"encoding/binary"
)

// H1 to H3 as SHA1

type MD4_t struct {
	H [4]uint32
	Data []byte
}

func Bit_padding_le(message_len int) []byte {
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
	binary.LittleEndian.PutUint64(padding[len(padding) - 8:], message_len_bits)

	return padding
}

func pad_le(data []byte) []byte {
	return append(data, Bit_padding_le(len(data))...)
}

func f(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func g(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func h(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func (s * MD4_t) process_chunk(chunk []byte) {
	var words [16]uint32

	for i := 0; i < 16; i++ {
		words[i] = binary.LittleEndian.Uint32(chunk[i * 4: (i + 1) * 4])
	}

	a, b, c, d := s.H[0], s.H[1], s.H[2], s.H[3]

	for i := 0; i < 16; i++ {
		switch i % 4 {
		case 0:
			a = leftrotate(a + f(b,c,d) + words[i], 3)
		case 1:
			d = leftrotate(d + f(a,b,c) + words[i], 7)
		case 2:
			c = leftrotate(c + f(d,a,b) + words[i], 11)
		case 3:
			b = leftrotate(b + f(c,d,a) + words[i], 19)
		}
	}

	for i := 0; i < 16; i++ {
		index := ((i * 4) + (i / 4)) % 16
		switch i % 4 {
		case 0:
			a = leftrotate(a + g(b,c,d) + words[index] + 0x5A827999, 3)
		case 1:
			d = leftrotate(d + g(a,b,c) + words[index] + 0x5A827999, 5)
		case 2:
			c = leftrotate(c + g(d,a,b) + words[index] + 0x5A827999, 9)
		case 3:
			b = leftrotate(b + g(c,d,a) + words[index] + 0x5A827999, 13)
		}
	}
	
	for i := 0; i < 16; i++ {
		// could be easier to just list all 16 here
		index := ((i & 1) << 3) + 
		         ((i & 2) << 1) +
		         ((i & 4) >> 1) +
		         ((i & 8) >> 3)
		switch i % 4 {
		case 0:
			a = leftrotate(a + h(b,c,d) + words[index] + 0x6ED9EBA1, 3)
		case 1:
			d = leftrotate(d + h(a,b,c) + words[index] + 0x6ED9EBA1, 9)
		case 2:
			c = leftrotate(c + h(d,a,b) + words[index] + 0x6ED9EBA1, 11)
		case 3:
			b = leftrotate(b + h(c,d,a) + words[index] + 0x6ED9EBA1, 15)
		}
	}

	s.H[0] = s.H[0] + a
	s.H[1] = s.H[1] + b 
	s.H[2] = s.H[2] + c
	s.H[3] = s.H[3] + d
}

func (s *MD4_t) Process() {
	for len(s.Data) > 0 {
		s.process_chunk(s.Data[:64])
		s.Data = s.Data[64:]
	}
}

func (s *MD4_t) Finalise() []byte {
	result := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(result[i * 4:(i + 1) * 4], s.H[i])
	}

	return result
}

func (s *MD4_t) Init(data []byte) {
	s.H[0] = H0
	s.H[1] = H1
	s.H[2] = H2
	s.H[3] = H3

	s.Data = data
}

func MD4(data []byte) []byte {
	data = pad_le(data)
	s := MD4_t{}
	s.Init(data)
	s.Process()

	return s.Finalise()
}

func MD4Sign(key, data []byte) []byte {
	return MD4(append(key, data...))
}

