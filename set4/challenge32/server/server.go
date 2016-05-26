package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"cryptopals/utils"
)

var key []byte = []byte("hello this is key")
var response_string = "{\"status\": \"ok\", \"file\": \"%s\", \"signature\": \"%s\"}\n"

var hash_length int64

const DELAY time.Duration = 10 * time.Millisecond

func insecure_compare(known, test []byte) bool {
	if len(known) != len(test) {
		return false
	}

	for i, v := range known {
		if v != test[i] {
			return false
		}
		time.Sleep(DELAY)
	}

	return true
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/json")
	w.Header().Set("Connection", "Close")

	file := r.FormValue("file")
	signature := r.FormValue("signature")

	if file == "" {
		w.WriteHeader(http.StatusOK)
		file = "file"
		signature = hex.EncodeToString(utils.HMAC_SHA1(key, []byte(file)))
		w.Write([]byte(fmt.Sprintf(response_string, file, signature)))
		return
	}

	calculated := utils.HMAC_SHA1(key, []byte(file))
	calculated = calculated[:hash_length]
	signature_bytes, e := hex.DecodeString(signature)

	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"status\": \"invalid signature\"}\n"))
		return
	}

	if insecure_compare(calculated, signature_bytes) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{\"status\": \"ok\"}\n"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"status\": \"unauthorized\"}\n"))
	}
}

func handleSignal(c chan os.Signal) {
	<-c
	fmt.Println("Exiting")
	os.Exit(0)
}

func main() {
	c := make(chan os.Signal, 1)
	go handleSignal(c)
	signal.Notify(c, os.Interrupt)

	if len(os.Args) == 2 {
		var e error
		hash_length, e = strconv.ParseInt(os.Args[1], 0, 0)
		if e != nil {
			fmt.Println("Arg must be an int (length of hash to check)")
			os.Exit(1)
		}
		fmt.Printf("Using first %s bytes of hash\n", os.Args[1])
	} else {
		hash_length = 20
	}

	fmt.Println("Starting server...")

	http.HandleFunc("/test", handler)
	http.ListenAndServe(":8888", nil)
}
