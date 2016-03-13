package main

import (
	"cryptopals/utils"
	"fmt"
)

func main() {
	validInput := []byte("ICE ICE BABY\x04\x04\x04\x04")
	stripped, error := utils.CheckAndStripPKCS7(validInput)

	if error != nil {
		fmt.Println(error.Error())
	} else {
		fmt.Printf("%q\n", stripped)
	}

	invalidInputs := [...][]byte{[]byte("ICE ICE BABY\x05\x05\x05\x05"), []byte("ICE ICE BABY\x01\x02\x03\x04")}

	for _, input := range(invalidInputs) {
		stripped, error = utils.CheckAndStripPKCS7(input)

		if error != nil {
			fmt.Println(error.Error())
		} else {
			fmt.Printf("%q\n", stripped)
		}
	}
}