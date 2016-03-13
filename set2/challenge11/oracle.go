package main

import (
  "math/rand"
  "cryptopals/utils"
  "fmt"
  // "encoding/base64"
)

func encryptionOracle(input []byte) []byte {
  input = append(utils.GenKey(5 + rand.Intn(6)), input...)
  input = append(input, utils.GenKey(5 + rand.Intn(6))...)

  input = utils.PKCS7(input, 16)

  if rand.Intn(2) == 0 {
    return utils.AesEcbEncrypt(input, utils.GenKey(16))
  } else {
    return utils.AesCbcEncrypt(input, utils.GenKey(16), utils.GenKey(16)) 
  }
}

func main() {
  for i := 0; i < 10; i++ {
    fmt.Println(utils.DetectEcbOrCbc(encryptionOracle))
  }
}

func init() {
  rand.Seed(11)
}