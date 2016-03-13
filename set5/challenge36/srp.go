package main

import (
	"math/big"
	"cryptopals/utils"
	"crypto/sha256"
	"bytes"
	"fmt"
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
	xH := utils.SHA1(append(salt, []byte(password)...))
	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(g, x, N)
	db[username] = &pw_entry{salt: salt, v: v}
}

func main() {
	username, password := "user@example.com", "password"

	fmt.Println("C: creating account")
	create_account(username, password)

	c := make(chan Message)
	go do_server(c)

	client := utils.InitNewDH(N, g)
	fmt.Println("C: sending INIT")
	c <- Message{message_type: INIT, I: []byte(username), cert: client.Public}

	message := <- c
	fmt.Println("C: received CHAL")
	uH := sha256.Sum256(append(client.Public.Bytes(), message.cert.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	xH := utils.SHA1(append(message.hash, []byte("password")...))
	x := new(big.Int).SetBytes(xH)
	//S = (B - k * g**x)**(a + u * x) % N
	S_1 := new(big.Int).Sub(message.cert, new(big.Int).Mul(k, new(big.Int).Exp(g, x, N)))
	S_2 := new(big.Int).Add(client.Secret, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(S_1, S_2, N)

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


