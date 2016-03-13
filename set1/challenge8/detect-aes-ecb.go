package main

import "fmt"
import "io/ioutil"
import "encoding/hex"
import "strings"

// import "cryptopals/utils"

func main() {
  data, _ := ioutil.ReadFile("./8.txt")

  hex_strings := strings.Split(string(data), "\n")

  for i, hex_string := range(hex_strings) {
    data, _ := hex.DecodeString(string(hex_string))

    if len(data) == 0 {
      continue
    }

    repeated := repeatedBlocks(data)
    if repeated > 0 {
      fmt.Printf("%3d: %d, %s\n", i, repeated, hex_string)
      // fmt.Printf("%q\n", utils.AesEcbDecrypt(data, []byte("yellow submarine")))

    }
  }
}

func repeatedBlocks(data []byte) int {
  counts := make(map[[16]byte]int)

  for len(data) > 0 {
    var block [16]byte
    copy(block[:], data[:16])

    counts[block]++
    data = data[16:] 
  }

  repeated_blocks := 0
  for _, v := range(counts) {
    if v > 1 {
      repeated_blocks += v
    }
  }

  return repeated_blocks
}