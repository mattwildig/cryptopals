package main

import "cryptopals/utils"
import "fmt"

func main() {
  input := "YELLOW SUBMARINE"

  padded := utils.PKCS7([]byte(input), 20)
  expected := "YELLOW SUBMARINE\x04\x04\x04\x04"

  fmt.Printf("%q\n", padded)
  fmt.Printf("Strings match: %t\n", string(padded) == expected)
}