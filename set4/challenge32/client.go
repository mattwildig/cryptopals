package main

import (
	"fmt"
	// "cryptopals/utils"
	"encoding/hex"
	"net/http"
	"time"
)

var url_string = "http://localhost:8888/test?file=%s&signature=%s"

const NUM_REQUESTS = 5


func main() {


	file := "hello"
	signature_bytes := make([]byte, 20)
	// signature_times := make([]byte, 20)

	client := &http.Client{}

	for pos := 0; pos < 20; pos ++ {
		// fmt.Printf("Finding char %d\n", pos)

		char_times := make([]time.Duration, 256)
		for i := 0; i < NUM_REQUESTS; i++ {
			for c := 0; c < 256; c++ {
				// fmt.Printf("Trying %d\n", i)
				signature_bytes[pos] = byte(c)
				signature := hex.EncodeToString(signature_bytes)
				url := fmt.Sprintf(url_string, file, signature)

				req, e := http.NewRequest("GET", url, nil)
				if e != nil {
					fmt.Printf("Error: %s\n", e.Error())
					panic("Error! An error has happened!")
				}
				req.Header.Add("Connection", "Close")

				start := time.Now()
				resp, e := client.Do(req)
				request_dur := time.Since(start)

				if e != nil {
					fmt.Printf("Error: %s\n", e.Error())
					panic("Error! An error has happened!")
				}

				resp.Body.Close()

				char_times[c] += request_dur

			}
		}

		max_c := -1
		max_d := time.Duration(0.0)
		for c, d := range char_times {
			if d > max_d {
				max_d = d
				max_c = c
			}
		}

		signature_bytes[pos] = byte(max_c)
		fmt.Printf("After char %2d: %s\n", pos, hex.EncodeToString(signature_bytes))
	}

	
	fmt.Println(signature_bytes)
}
