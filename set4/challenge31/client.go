package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var url_string = "http://localhost:8888/test?file=%s&signature=%s"

func main() {

	file := "hello"
	signature_bytes := make([]byte, 20)
	pos := 0

	if len(os.Args) == 2 {
		starting_bytes, e := hex.DecodeString(os.Args[1])
		if e != nil {
			fmt.Println("Error decoding starting bytes, must be valid hex string")
			os.Exit(1)
		}
		fmt.Printf("Starting with (assuming correct):\n\t%s\n", os.Args[1])
		copy(signature_bytes, starting_bytes)
		pos = len(starting_bytes)
	}

	for ; pos < 20; pos ++ {

		max_time := time.Duration(0)
		this_byte := -1
		for i:= 0; i < 256; i++ {

			fmt.Printf("\rTrying: %02x", i)

			signature_bytes[pos] = byte(i)
			signature := hex.EncodeToString(signature_bytes)
			url := fmt.Sprintf(url_string, file, signature)

			start := time.Now()
			resp, e := http.Get(url)

			request_dur := time.Since(start)

			if e != nil {
				panic("Error! An error has happened!")
			}

			resp.Body.Close()

			if request_dur > max_time {
				max_time = request_dur
				this_byte = i
			}

		}
		signature_bytes[pos] = byte(this_byte)
		fmt.Printf("\rAfter char %d: %s\n", pos, hex.EncodeToString(signature_bytes))
	}

	signature_hex := hex.EncodeToString(signature_bytes)
	fmt.Printf("Final signature: %s\n", signature_hex)

	url := fmt.Sprintf(url_string, file, signature_hex)
	resp, e := http.Get(url)
	if e != nil {
		panic("Error! An error has happened!")
	}
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("Server response with final signature:\n\t%s\n", body)
}
