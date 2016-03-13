package main

import (
  "fmt"
  "cryptopals/utils"
  "io/ioutil"
  "encoding/base64"
)

func main() {
  encoded_data, _ := ioutil.ReadFile("./10.txt")
  data, _ := base64.StdEncoding.DecodeString(string(encoded_data))

  key := []byte("YELLOW SUBMARINE")

  iv := make([]byte, 16)

  decrypted := utils.AesCbcDecrypt(data, key, iv)

  fmt.Printf("%s\n", decrypted)
}
