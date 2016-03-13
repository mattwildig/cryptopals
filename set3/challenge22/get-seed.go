package main

import (
	"fmt"
	"cryptopals/utils"
	"time"
	"math/rand"
)

func main() {
	num := getNum()

	now := uint32(time.Now().Unix())

	fmt.Println("Calculating...")
	for guess := (now - 1030); guess <= now; guess++ {
		m := utils.Mersenne{}
		m.Init_mersenne(guess)

		if m.NextInt() == num {
			fmt.Printf("Found seed: %d\n", guess)
			return
		}
	}
	fmt.Printf("Failed to find seed\n")
}

func getNum() uint32 {
	d := rand.Intn(960)

	fmt.Println("Waiting...")
	time.Sleep(time.Duration((d + 40)) * time.Second)

	s := uint32(time.Now().Unix())

	m := utils.Mersenne{}

	m.Init_mersenne(s)

	time.Sleep(time.Duration((1000 - d)) * time.Second)

	fmt.Printf("Seed: %d\n", s)
	num := m.NextInt()
	fmt.Printf("1st number is %d\n", num)

	return num
}