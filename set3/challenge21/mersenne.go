package main

import (
	"fmt"
	"cryptopals/utils"
)

func main() {
	m := utils.Mersenne{}
	m.Init_mersenne(0)

	for i := 0; i < 20; i++ {
		fmt.Println(m.NextInt())
	}

	// t := uint32(2886369164)
	// count := 0

	// fmt.Println("Starting...")
	// for t != m.NextInt() {
	// 	count++
	// 	if count % 10000000 == 0 {
	// 		fmt.Println(count)
	// 	}
	// }

	// fmt.Println(t)
	// fmt.Println(count)

}