package main

import "fmt"
import "io/ioutil"
import "encoding/base64"

import "cryptopals/utils"

func main() {
  data64, _ := ioutil.ReadFile("./7.txt")
  data, _ := base64.StdEncoding.DecodeString(string(data64))

  key := "YELLOW SUBMARINE"

  decoded := utils.AesEcbDecrypt(data, []byte(key))

  fmt.Println(string(decoded))
}
