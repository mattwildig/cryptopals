package main

import (
	"fmt"
	"math/big"
	"os"

	"cryptopals/utils"
)

const KEY_BITS int = 256
const RSA_EXPONENT = 3

var key utils.RSA = utils.CreateRSA(KEY_BITS, RSA_EXPONENT)

var two = big.NewInt(2)
var three = big.NewInt(3)

var B, B2, B3, B3m1 *big.Int

var oracleCount uint64 = 0

func init() {
	B = new(big.Int)
	B2 = new(big.Int)
	B3 = new(big.Int)
	B3m1 = new(big.Int)
	exp := int64(((KEY_BITS / 8) - 2) * 8)
	B.Exp(two, big.NewInt(exp), key.N) // shouldn’t wrap
	B2.Mul(B, two)
	B3.Mul(B, three)
	B3m1.Sub(B3, utils.One)
}

type Interval struct {a, b *big.Int} // Papers use a, b rather than upper, lower

func NewInterval() *Interval {
	return &Interval{new(big.Int), new(big.Int)}
}

func Oracle(t *big.Int) bool {
	t = key.Decrypt(t)
	oracleCount++
	if t.Cmp(key.N) == 1 {
		panic("t too big")
	}
	b := t.Bytes()
	return len(b) == len(key.N.Bytes()) - 1 && b[0] == 0x02
}

// x / y, rounded up
func Ceil(x, y *big.Int) *big.Int {
	var c, m big.Int
	c.DivMod(x, y, &m)
	if !utils.BigZero(&m) {
		c.Add(&c, utils.One)
	}

	return &c
}

func FindNewInterval(s, r *big.Int) *Interval {
	// (2B + rn) / si ≤ m0 ≤ (3B - 1 + rn) / si

	interval := NewInterval()
	rn := new(big.Int).Mul(r, key.N)

	interval.a.Add(B2, rn)
	interval.a = Ceil(interval.a, s)

	interval.b.Add(B3m1, rn).Div(interval.b, s)

	return interval
}

func RRange(s *big.Int, i *Interval) (*big.Int, *big.Int) {
	var r_min, r_max big.Int

	r_min.Mul(i.a, s).Sub(&r_min, B3m1)
	r_min.Set(Ceil(&r_min, key.N))

	r_max.Mul(i.b, s).Sub(&r_max, B2).Div(&r_max, key.N)

	return &r_min, &r_max
}

func max(a, b *big.Int) *big.Int {
	if a.Cmp(b) == 1 {
		return a
	} else {
		return b
	}
}

func min(a, b *big.Int) *big.Int {
	if a.Cmp(b) == -1 {
		return a
	} else {
		return b
	}
}

func IntersectInterval(a, b *Interval) *Interval {
	newA := max(a.a, b.a)
	newB := min(a.b, b.b)

	if newA.Cmp(newB) <= 0 {
		return &Interval{newA, newB}
	} else {
		return nil
	}
}

func BinarySearch(i *Interval, s_previous, c0 *big.Int) *big.Int {
	r := new(big.Int)
	r.Mul(i.b, s_previous).Sub(r, B2).Mul(r, two)
	r = Ceil(r, key.N)

	rn := new(big.Int)
	s := new(big.Int)
	ci := new(big.Int)

	found:
	for {
		rn.Mul(r, key.N)
		s.Add(B2, rn)
		s = Ceil(s, i.b)

		upper := new(big.Int)
		upper.Add(B3m1, rn).Div(upper, i.a)

		for s.Cmp(upper) <= 0 {
			// mi.Mul(m0, s).Mod(mi, key.N) // simulated
			factor := key.Encrypt(s)
			ci.Mul(c0, factor)
			if (Oracle(ci)) {
				break found
			}
			s.Add(s, utils.One)
		}
		r.Add(r, utils.One)
	}
	return s

}

func checkRs(r_min, r_max *big.Int) {
	if r_max.Cmp(r_min) != 0 {
		fmt.Println("[!] More than one possible value of r, exiting!")
		diff := new(big.Int)
		diff.Sub(r_max, r_min).Add(diff, utils.One)
		fmt.Printf("    min: %s, max: %s, count: %s\n", r_min, r_max, diff)
		os.Exit(1)
	}
}

func reportRange(i *Interval) {
	fmt.Printf("    Range from %s\n", i.a)
	fmt.Printf("            to %s\n", i.b)
	var t big.Int
	fmt.Printf("    Covers: %s\n", t.Sub(i.b, i.a))
}

func main() {
	message := []byte("kick it, CC")
	message = utils.PKCS15Pad(message, KEY_BITS)
	message = key.EncryptBytes(message)

	c0 := new(big.Int)
	c0.SetBytes(message)

	s := Ceil(key.N, B3)
	// fmt.Printf("[-] Start value for s: %s\n", s)

	ci := new(big.Int)

	fmt.Printf("[-] Finding first s...")
	for {
		// mi.Mul(m0, s).Mod(mi, key.N) // simulated
		factor := key.Encrypt(s)
		ci.Mul(c0, factor)

		if Oracle(ci) {
			break
		}
		s.Add(s, utils.One)
	}
	fmt.Printf("done\n")
	fmt.Printf("[*] Found s: %s\n", s)

	start_interval := Interval{B2, B3m1}
	r_min, r_max := RRange(s, &start_interval)
	checkRs(r_min, r_max)

	interval := FindNewInterval(s, r_min)
	interval = IntersectInterval(&start_interval, interval)
	// reportRange(interval)

	for {
		new_s := BinarySearch(interval, s, c0)

		fmt.Printf("[*] New s: %s\n", new_s)

		r_min, r_max = RRange(new_s, interval)
		checkRs(r_min, r_max)

		this_interval := FindNewInterval(new_s, r_min)
		this_interval = IntersectInterval(interval, this_interval)

		if this_interval == nil {
			fmt.Println("[!] Next interval is nil - no overlap!")
			os.Exit(1)
		}

		// reportRange(intersection)
		interval = this_interval

		if interval.a.Cmp(interval.b) == 0 {
			break
		}

		s = new_s
	}

	fmt.Println()
	fmt.Println("[*] Found message:")
	decrypted := utils.PKCS15Unpad(interval.a.Bytes())
	fmt.Printf("    %q\n", decrypted)
	fmt.Printf("    %d calls to oracle\n", oracleCount)
}
