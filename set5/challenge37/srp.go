package main

import (
	"math/big"
	"cryptopals/utils"
	"crypto/sha256"
	"bytes"
	"fmt"
	"os"
)

var N = utils.P
var g = big.NewInt(2)
var k = big.NewInt(3)

type pw_entry struct {
	salt []byte
	v, cert *big.Int
}

type ServerData map[string]*pw_entry
var db = make(ServerData)

type MessageType int

const (
	INIT MessageType = iota
	CHAL
	CHECK
	OK
	FAIL
)

type Message struct {
	message_type MessageType
	I, hash []byte
	cert *big.Int
}

func do_server(c chan Message) {
	// db := make(ServerData)
	server := utils.InitNewDH(N, g)
	var message Message

	for {
		message = <- c
		switch message.message_type {
		case INIT:
			fmt.Println("S: received INIT")
			pw := db[string(message.I)]
			pw.cert = message.cert
			challenge := new(big.Int).Add(new(big.Int).Mul(k, pw.v), server.Public)
			fmt.Println("S: sending CHAL")
			c <- Message{message_type: CHAL, hash: pw.salt, cert: challenge}
			continue
		case CHECK:
			fmt.Println("S: received CHECK")
			pw := db[string(message.I)]
			B :=new(big.Int).Add(new(big.Int).Mul(k, pw.v), server.Public)

			uH := sha256.Sum256(append(pw.cert.Bytes(), B.Bytes()...))
			u := new(big.Int).SetBytes(uH[:])

			fmt.Println("S: calculating S...")
			//S = (A * v**u) ** b % N
			S := new(big.Int).Exp(new(big.Int).Mul(pw.cert, new(big.Int).Exp(pw.v, u, N)), server.Secret, N)
			fmt.Println("S: done")
			K := sha256.Sum256(S.Bytes())

			if bytes.Equal(utils.HMAC_SHA1(K[:], pw.salt), message.hash) {
				fmt.Println("S: sending OK")
				c <- Message{message_type: OK}
			} else {
				fmt.Println("S: sending FAIL")
				c <- Message{message_type: FAIL}
			}

			continue
		}
	}

}

func create_account(username, password string){
	salt := utils.GenKey(16)
	xH := append(salt, []byte(password)...)
	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(g, x, N)
	db[username] = &pw_entry{salt: salt, v: v}
}

var client_cert *big.Int

func init() {
	if len(os.Args) != 2 {
		fmt.Println("Please specify client cert value to use")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "0":
		fmt.Println("Using client cert value of 0")
		client_cert = big.NewInt(0)
	case "N":
		fmt.Println("Using client cert value of N")
		client_cert = N
	case "N2":
		fmt.Println("Using client cert value of N ** 2")
		client_cert = new(big.Int).Mul(N, N)
	default:
		fmt.Printf("Invalid client cert value: %s\n", os.Args[1])
		os.Exit(1)
	}

}

func main() {
	username, password := "user@example.com", string(utils.GenKey(20))

	fmt.Println("C: creating account")
	create_account(username, password)

	c := make(chan Message)
	go do_server(c)

	//-------------------------------------

	fmt.Println("C: sending INIT")
	c <- Message{message_type: INIT, I: []byte(username), cert: client_cert}

	message := <- c
	fmt.Println("C: received CHAL")

	S := big.NewInt(0)

	K := sha256.Sum256(S.Bytes())

	c <- Message{message_type: CHECK, I: []byte(username), hash: utils.HMAC_SHA1(K[:], message.hash)}

	fmt.Println("C: sending CHECK")
	message = <- c
	if message.message_type == OK {
		fmt.Println("OK!")
	} else {
		fmt.Println("FAIL")
	}
}


