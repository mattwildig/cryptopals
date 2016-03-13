package main

import "cryptopals/utils"
import "fmt"
import "encoding/hex"

func main() {
  input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
  expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
  key := "ICE"

  result := hex.EncodeToString(utils.RepeatingKeyXOR([]byte(input), []byte(key)))

  fmt.Printf("Result: %q\n", result)
  fmt.Printf("Result matches expected: %t\n", result == expected)
}