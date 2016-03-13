package main

import "encoding/hex"
import "fmt"

import "cryptopals/utils"

func main() {
  in1 := "1c0111001f010100061a024b53535009181c"
  in2 := "686974207468652062756c6c277320657965"

  expected := "746865206b696420646f6e277420706c6179"

  in1_slice, _ := hex.DecodeString(in1)
  in2_slice, _ := hex.DecodeString(in2)

  fmt.Printf("in1: %q\n", string(in1_slice))
  fmt.Printf("in2: %q\n", string(in2_slice))

  result_slice, _ := utils.FixedXOR(in1_slice, in2_slice)

  fmt.Printf("in2: %q\n", string(result_slice))

  result := hex.EncodeToString(result_slice)

  fmt.Printf("Result string: %q\n", result)
  fmt.Printf("result matches expected: %t\n", result == expected)
}