package main

import "io/ioutil"
import "strings"
import "encoding/hex"
import "fmt"

import "cryptopals/utils"

func main() {
  data, err := ioutil.ReadFile("./4.txt")

  if err != nil {
    fmt.Println("Can’t read file, you’re probably in the wrong directory!")
    return
  }

  ciphers := strings.Split(string(data), "\n")

  current_best := utils.DecryptPossibility{0, nil, 0}
  current_best_index := -1

  for index, cipher := range(ciphers) {
    input, _ := hex.DecodeString(cipher)

    this := utils.DecryptSingleByteXOR(input)

    if this.Score > current_best.Score {
      current_best = this
      current_best_index = index
    }

  }
  fmt.Printf("Index: %d, Key: %q , Score: %f: %q\n", current_best_index, current_best.Key, current_best.Score, string(current_best.Decoded))  

}