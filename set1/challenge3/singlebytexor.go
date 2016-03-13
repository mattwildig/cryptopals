package main

import "cryptopals/utils"
import "encoding/hex"
import "fmt"

func main() {
  input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  result := utils.DecryptSingleByteXOR(input)

  fmt.Printf("Key: %d, Score: %f: %q\n", result.Key, result.Score, string(result.Decoded)) 
}
