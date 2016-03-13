package main

import (
	"math/big"
	"math/rand"
	"cryptopals/utils"
	"bytes"
	"fmt"
	"time"
)

var N = utils.P
var g = big.NewInt(2)

// from http://splashdata.com/press/worst-passwords-of-2014.htm
var Passwords = [...]string{"123456", "password", "12345", "12345678", "qwerty",
		"123456789", "1234", "baseball", "dragon", "football", "1234567",
		"monkey", "letmein", "abc123", "111111", "mustang", "access", "shadow",
		"master", "michael", "superman", "696969", "123123", "batman", "trustno1"}

type MessageType int

const (
	ID MessageType = iota
	CHAL
	VERIFY
	OK
	FAIL
)

type Message struct {
	m_type MessageType
	i string
	u, cert *big.Int
	salt []byte
	digest []byte
}

type pw_entry struct {
	salt []byte
	cert, u, v *big.Int
}

type ServerData map[string]*pw_entry
var db = make(ServerData)

func do_server(c chan Message) {
	server := utils.InitNewDH(N, g)
	var msg Message

	for {
		msg = <- c

		switch msg.m_type {
		case ID:
			pw := db[string(msg.i)]

			pw.cert = msg.cert
			u := new(big.Int).SetBytes(utils.GenKey(16))
			pw.u = u
			c <- Message{m_type: CHAL, salt: pw.salt, cert: server.Public, u: u}
			continue
		case VERIFY:
			pw := db[string(msg.i)]

			//S = (A * v ** u)**b % n
			S_1 := new(big.Int).Mul(pw.cert, new(big.Int).Exp(pw.v, pw.u, N))
			S := new(big.Int).Exp(S_1, server.Secret, N)
			K := utils.SHA1(S.Bytes())  // until we have our own SHA256

			if bytes.Equal(utils.HMAC_SHA1(K, pw.salt), msg.digest) {
				c <- Message{m_type: OK}
			} else {
				c <- Message{m_type: FAIL}
			}
			continue
		}
	}
}

func mitm(c chan Message) {
	mitm := utils.InitNewDH(N, g) // could probably choose values to make calculation easier
	var msg Message

	msg = <- c
	cert := msg.cert
	salt := []byte{}
	u := big.NewInt(1)
	c <- Message{m_type: CHAL, salt: salt, cert: mitm.Public, u: u}

	msg = <- c

	for _, password := range Passwords {

		xH := utils.SHA1(append(salt, []byte(password)...))
		x := new(big.Int).SetBytes(xH)
		v := new(big.Int).Exp(g, x, N)

		S_1 := new(big.Int).Mul(cert, new(big.Int).Exp(v, u, N))
		S := new(big.Int).Exp(S_1, mitm.Secret, N)
		K := utils.SHA1(S.Bytes())

		if bytes.Equal(utils.HMAC_SHA1(K, salt), msg.digest) {
			fmt.Printf("Found password: %s\n", password)
			break
		}
	}

	//really this would be sent immediately and then attack would be offline
	c <- Message{m_type: FAIL}
}

func create_account(user, password string) {
	salt := utils.GenKey(16)
	xH := utils.SHA1(append(salt, []byte(password)...))
	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(g, x, N)
	db[user] = &pw_entry{salt: salt, v: v}
}


func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	user, password := "user@example.com", Passwords[rand.Intn(len(Passwords))]
	fmt.Printf("Using password: %s\n", password)
	create_account(user, password)

	c := make(chan Message)
	// go do_server(c)
	go mitm(c)

	client := utils.InitNewDH(N, g)

	c <- Message{m_type: ID, i: user, cert: client.Public}

	msg := <- c

	xH := utils.SHA1(append(msg.salt, []byte(password)...))
	x := new(big.Int).SetBytes(xH)
	//S = B**(a + ux) % n
	S_1 := new(big.Int).Add(client.Secret, new(big.Int).Mul(msg.u, x))
	S := new(big.Int).Exp(msg.cert, S_1, N)
	K := utils.SHA1(S.Bytes())

	c <- Message{m_type: VERIFY, i: user, digest: utils.HMAC_SHA1(K, msg.salt)}

	msg = <-c

	if msg.m_type == OK {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL")
	}
}
