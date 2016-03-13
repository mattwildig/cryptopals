package main

import (
	"encoding/base64"
	"cryptopals/utils"
	"fmt"
)

var data64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
var data = getData()

func getData() []byte {
	it, _ := base64.StdEncoding.DecodeString(data64)
	return it
}

func main() {
	result := make([]byte, len(data))
	e := utils.AesCtr(result, data, []byte("YELLOW SUBMARINE"), make([]byte, 8))
	if e != nil {
		fmt.Println("Error in AesCtr")
	}
	fmt.Printf("%q\n", result)
}