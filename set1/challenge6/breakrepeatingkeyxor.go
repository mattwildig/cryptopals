package main

import "fmt"
import "io/ioutil"
import "encoding/base64"

import "cryptopals/utils"

func main() {
  data64, _ := ioutil.ReadFile("./6.txt")
  data, _ := base64.StdEncoding.DecodeString(string(data64))

  result, key := utils.DecryptRepeatingKeyXOR(data)

  fmt.Printf("%q\n\n", key)
  fmt.Printf("%s\n", string(result))
}