package utils

import (
	"errors"
	"encoding/binary"
)

const (
	// W = 32
	N = 624
	M = 397
	R = 31
	LOWER_BITS uint32 = (1 << R) - 1
	UPPER_BITS uint32 = ^LOWER_BITS
	A = 0x9908B0DF
	B_MASK = 0x9D2C5680
	C_MASK = 0xEFC60000
	S_SHIFT = 7
	T_SHIFT = 15
	U_SHIFT = 11
	D_MASK = 0xFFFFFFFF
	L_SHIFT = 18
	F = 1812433253
)

type Mersenne struct {
	State_vec [N]uint32
	pos int
}

func (m *Mersenne) NextInt() uint32 {
	temp := twist_transform((m.State_vec[m.pos] & UPPER_BITS) | (m.State_vec[(m.pos + 1) % N] & LOWER_BITS))
	temp = temp ^ m.State_vec[(m.pos + M) % N]

	m.State_vec[m.pos] = temp
	m.pos = (m.pos + 1) % N

	return temper(temp)
}

func twist_transform(temp uint32) uint32 {
	low := (temp & 1) == 1
	temp = temp >> 1
	if low {
		return temp ^ A
	} else {
		return temp
	}
}

func temper(x uint32) uint32 {
	x ^= ((x >> U_SHIFT) & D_MASK)
	x ^= ((x << S_SHIFT) & B_MASK)
	x ^= ((x << T_SHIFT) & C_MASK)
	return x ^ (x >> L_SHIFT)
}

func Untemper(x uint32) uint32 {
	x = remove_shift_right(x, L_SHIFT)
	x = remove_shift_left_and_mask(x, T_SHIFT, C_MASK)
	x = remove_shift_left_and_mask(x, S_SHIFT, B_MASK)
	x = remove_shift_right(x, U_SHIFT)

	return x
}

func remove_shift_right(x uint32, shift uint32) uint32 {

	for ; shift < 32; shift *= 2 {
		x ^= (x >> shift)
	}

	return x
}

func remove_shift_left_and_mask(x, shift, mask uint32) uint32 {
	var r uint32 = 0
	for t := uint32(0); t < 32; t += shift {
		r = x ^ (r << shift) & mask
	}

	return r
}

func (m *Mersenne) Init_mersenne(seed uint32) {
	m.State_vec[0] = seed
	for i := 1; i < N; i++ {
		m.State_vec[i] = 0xFFFFFFFF & (F * (m.State_vec[i-1] ^ (m.State_vec[i-1] >> (30))) + uint32(i))
	}
}

func MersenneEncrypt(into, data []byte, key uint16) error {
	if len(into) < len(data) {
		return errors.New("Target buffer too small")
	}

	m := Mersenne{}
	m.Init_mersenne(uint32(key))
	var buf [4]byte

	for len(data) >= 4 {
		binary.BigEndian.PutUint32(buf[:], m.NextInt())
		FixedXORBuffer(into[:4], data[:4], buf[:])
		into = into[4:]
		data = data[4:]
	}

	binary.BigEndian.PutUint32(buf[:], m.NextInt())
	FixedXORBuffer(into, data, buf[:len(data)])

	return nil
}
