package main

import (
  "cryptopals/utils"
  "encoding/base64"
  "fmt"
  "bytes"
)

var secretKey = utils.GenKey(16)
const unkownDataString = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

var unkownData = getUnknowData()

func getUnknowData() []byte {
  data, _ := base64.StdEncoding.DecodeString(unkownDataString)
  return data
}

func encryptionOracle(input []byte) []byte {
  input = append(input, unkownData...)

  input = utils.PKCS7(input, 16)

  return utils.AesEcbEncrypt(input, secretKey)
}

func main() {

  prefix := []byte("")
  startLen := len(encryptionOracle(prefix))
  blocksize := 0

  for {
    prefix = append(prefix, 'A')
    nextLen := len(encryptionOracle(prefix))

    if startLen != nextLen {
      blocksize = nextLen - startLen
      fmt.Printf("Blocksize: %d\n", blocksize)
      break
    }
  }

  fmt.Printf("Mode: %s\n", utils.DetectEcbOrCbc(encryptionOracle))

  //-----------

  knownBuffer := make([]byte, len(unkownData))

  for knownLen := 0; knownLen < len(unkownData); knownLen++ {
    findNextByte(knownBuffer, knownLen, blocksize)
  }

  fmt.Printf("%s\n", knownBuffer)
}

func findNextByte(known []byte, knownLen, blocksize int) {

  blockIndex := (knownLen / blocksize) * blocksize

  prefixLen := blocksize - (knownLen % blocksize) - 1
  prefix := make([]byte, prefixLen)
  encryptedBlock := encryptionOracle(prefix)[blockIndex : blockIndex + blocksize]

  prefix = append(prefix, known[:knownLen]...)

  for i := 0; i <= 256; i++ {
    res := encryptionOracle(append(prefix, byte(i)))[blockIndex : blockIndex + blocksize]

    if bytes.Equal(res, encryptedBlock) {
      known[knownLen] = byte(i)
      return
    }
  }
  panic("Decrypt not found")
}











