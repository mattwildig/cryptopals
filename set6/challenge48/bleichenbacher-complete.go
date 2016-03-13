package main

import (
	"fmt"
	"math/big"

	"cryptopals/utils"
)

const KEY_BITS int = 512
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

func getEncryptedMessage() *big.Int {
	message := []byte("kick it, CC")
	message = utils.PKCS15Pad(message, KEY_BITS)
	message = key.EncryptBytes(message)

	c0 := new(big.Int)
	c0.SetBytes(message)

	return c0
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

func reportRange(i *Interval) {
	fmt.Printf("    Range from %s\n", i.a)
	fmt.Printf("            to %s\n", i.b)
	var t big.Int
	fmt.Printf("    Covers: %s\n", t.Sub(i.b, i.a))
}

func LinearSearch(start, c0 *big.Int) *big.Int {
	ci := new(big.Int)
	s := new(big.Int)
	s.Set(start)
	for {
		// mi.Mul(m0, s).Mod(mi, key.N) // simulated
		factor := key.Encrypt(s)
		ci.Mul(c0, factor)

		if Oracle(ci) {
			break
		}
		s.Add(s, utils.One)
	}
	return s
}

func addIfNotPresent(set []*Interval, new_interval *Interval) []*Interval {
	for _, i := range set {
		if i.a.Cmp(new_interval.a) == 0 && i.b.Cmp(new_interval.b) == 0 {
			// interval is already in set
			return set
		}
	}
	return append(set, new_interval)
}

func main() {
	c0 := getEncryptedMessage()

	s := Ceil(key.N, B3)

	fmt.Printf("[-] Finding first s...")

	s = LinearSearch(s, c0)

	fmt.Printf("done\n")
	fmt.Printf("[*] Found s: %s\n", s)

	interval := NewInterval()
	interval.a = B2
	interval.b = B3m1

	M := make([]*Interval, 0)

	r_min, r_max := RRange(s, interval)

	r := new(big.Int)
	for r.Set(r_min); r.Cmp(r_max) <= 0; r.Add(r, utils.One) {
		this_interval := FindNewInterval(s, r_min)
		this_interval = IntersectInterval(this_interval, interval)

		if this_interval != nil {
			M = append(M, this_interval)
		}
	}

	var multi_intervals bool = false
	var print bool = true
	for {

		fmt.Printf("[-] Next iteration...\n")
		if print {
			fmt.Printf("    Len M: %d\n", len(M))
			fmt.Printf("    Current s: %s\n", s)
		}
		var new_s *big.Int
		if len(M) > 1 {
			fmt.Println("    Using linear search")
			new_s = LinearSearch(s.Add(s, utils.One), c0)
			print = true
			multi_intervals = true
		} else {
			fmt.Println("    Using binary search")
			new_s = BinarySearch(M[0], s, c0)
			print = false
		}
		if print {
			fmt.Printf("      found s: %s\n", new_s)
			fmt.Println("    Creating intervals")
		}

		next_M := make([]*Interval, 0)
		for i, interval := range(M) {
			if print {
				fmt.Printf("      interval: M[%d]\n", i)
			}
			r_min, r_max = RRange(new_s, interval)
			r := new(big.Int)
			for r.Set(r_min); r.Cmp(r_max) <= 0; r.Add(r, utils.One) {
				if print {
					fmt.Printf("        r: %s\n", r)
				}
				this_interval := FindNewInterval(new_s, r)
				this_interval = IntersectInterval(this_interval, interval)

				if this_interval != nil {
					if print {
						fmt.Println("          Appending interval:")
						fmt.Printf( "            %s\n", this_interval.a)
						fmt.Printf( "            %s\n", this_interval.b)
					}
					next_M = addIfNotPresent(next_M, this_interval)
				}
			}
		}

		s = new_s
		M = next_M

		if len(M) == 1 && M[0].a.Cmp(M[0].b) == 0 {
			break
		}

	}

	fmt.Println()
	fmt.Println("[*] Found message:")
	decrypted := utils.PKCS15Unpad(M[0].a.Bytes())
	fmt.Printf("    %q\n", decrypted)
	if multi_intervals {
		fmt.Println("    ** Used multiple intervals **")
	}
	fmt.Printf("    %d calls to oracle\n", oracleCount)
}
