package main

import (
	"fmt"
	// "cryptopals/utils"
	"encoding/hex"
	"net/http"
	"time"
)

var url_string = "http://localhost:8888/test?file=%s&signature=%s"

const NUM_REQUESTS int = 1


func main() {


	file := "hello"
	signature_bytes := make([]byte, 20)
	// signature_times := make([]byte, 20)

	for pos := 0; pos < 20; pos ++ {
		// fmt.Printf("Finding char %d\n", pos)

		max_time := time.Duration(0)
		this_byte := -1
		for i:= 0; i < 256; i++ {
			// fmt.Printf("Trying %d\n", i)
			signature_bytes[pos] = byte(i)
			signature := hex.EncodeToString(signature_bytes)
			url := fmt.Sprintf(url_string, file, signature)

			// total_char_time := time.Duration(0)
			// for i := 0; i < NUM_REQUESTS; i++ {
				start := time.Now()
				resp, e := http.Get(url)

				request_dur := time.Since(start)

				if e != nil {
					panic("Error! An error has happened!")
				}

				resp.Body.Close()

				// total_char_time += request_dur
			// }

			// avg_dur := total_char_time / time.Duration(NUM_REQUESTS)

			// if avg_dur > max_time {
			// 	max_time = avg_dur
			if request_dur > max_time {
				max_time = request_dur
				this_byte = i
			}

		}
		signature_bytes[pos] = byte(this_byte)
		fmt.Printf("After char %d: %s\n", pos, hex.EncodeToString(signature_bytes))
	}

	
	fmt.Println(signature_bytes)
}
