package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"
)

var url_string = "http://localhost:8888/test?file=%s&signature=%s"
const ITER_COUNT = 16000

func main() {
	file := "hello"

	// correct first byte is 19
	first_bytes := []byte{18, 19, 20}

	urls := make([]string, len(first_bytes))
	files := make([]*os.File, len(first_bytes))

	for i, b := range(first_bytes) {
		signature_bytes := make([]byte, 4)

		signature_bytes[0] = b

		signature := hex.EncodeToString(signature_bytes)
		urls[i] = fmt.Sprintf(url_string, file, signature)

		file, file_error := os.Create(fmt.Sprintf("times_%d.txt", i))
		files[i] = file
		if file_error != nil {
			panic("Error! An error has happened opening the file!")
		}
	}

	fmt.Println("Starting gathering stats...")

	for i := 0; i < ITER_COUNT; i++ {
		if i % 100 == 0 {
			fmt.Printf("\rIter %d\033[K", i)
		}

		if i != 0 && i % 4000 == 0 {
			time.Sleep(30 * time.Second)
		}

		for i, url := range(urls) {
			start := time.Now()
			resp, e := http.Get(url)

			request_dur := time.Since(start)

			if e != nil {
				panic(fmt.Sprintf("Error! An error has happened! %s", e))
			}

			resp.Body.Close()

			fmt.Fprintln(files[i], request_dur.Nanoseconds())
		}
	}

	fmt.Println("\rDone\033[K")
	for _, file := range(files) {
		file.Close()
	}


}