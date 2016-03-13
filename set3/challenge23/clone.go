package main

import (
	"cryptopals/utils"
	"fmt"
	"time"
)

func main() {
	m := utils.Mersenne{}
	clone := utils.Mersenne{}

	m.Init_mersenne(uint32(time.Now().Nanosecond()))

	for i := 0; i < 624; i ++ {
		next := m.NextInt()

		clone.State_vec[i] = utils.Untemper(next)
	}

	for i := 0; i < 10; i++ {
		fmt.Printf("Next predicted: %d, Next actual: %d\n", clone.NextInt(), m.NextInt())
	}
}