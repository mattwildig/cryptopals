package main

import (
	"bytes"
	"fmt"
	"strings"

	"cryptopals/utils"
)

type Message struct {
	message, iv, mac []byte
	ak bool
}

type KeyHolder struct {
	key []byte
}

type Server struct {
	KeyHolder
}

type Client struct {
	KeyHolder
}

func (s Server) validateMessage(m Message) bool {
	data := utils.AesCbcEncrypt(utils.PKCS7(m.message, 16), s.key, m.iv)
	calculated := data[len(data) - 16:]

	if bytes.Equal(calculated, m.mac) {
		return true
	} else {
		return false
	}
}

func (c Client) signMessage(m string) Message {
	iv := utils.GenKey(16)
	mb := []byte(m)

	data := utils.AesCbcEncrypt(utils.PKCS7(mb, 16), c.key, iv)
	mac := data[len(data) - 16:]

	return Message{mb, iv, mac, false}
}

// This function needs to be deliberately lenient for the attack to work
func parseMessage(m []byte) {
	s := string(m)
	parts := strings.Split(s, "&")
	// if len(parts) != 3 {
	// 	fmt.Println("Wrong message format")
	// 	return
	// }
	var from, to, amount string

	for _, p := range(parts) {
		pair := strings.Split(p, "=")
		if len(pair) != 2 {
			// fmt.Println("Wrong message format")
			continue
		}
		key := pair[0]
		val := pair[1]

		switch key {
		case "from":
			from = val
		case "to":
			to = val
		case "amount":
			amount = val
		}
	}
	if from == "" || to == "" || amount == "" {
		fmt.Println("Wrong message format")
	} else {
		fmt.Printf("Transferring %s from %s to %s\n", amount, from, to)
	}
}

func printGreen(m string) {
	s := fmt.Sprintf("\x1b[32m%s\x1b[m", m)
	fmt.Println(s)
}

func printRed(m string) {
	s := fmt.Sprintf("\x1b[31m%s\x1b[m", m)
	fmt.Println(s)
}

func runServer(ch chan Message, s Server) {

	for {
		message := <-ch
 
 		if s.validateMessage(message) {
 			printGreen("Valid message received")
			fmt.Printf("\t%q\n", message.message)
			parseMessage(message.message)
			ch <- Message{ak: true}
		} else {
			printRed("Inalid message!")
			fmt.Printf("\t%q\n", message.message)
			ch <- Message{ak: false}
		}
	}
}

func runClient(ch chan Message, c Client) {
	fmt.Println("Enter transaction:")
	var from, to, amount string
	fmt.Scanf("%s %s %s", &from, &to, &amount)

	message := fmt.Sprintf("from=%s&to=%s&amount=%s", from, to, amount)
	fmt.Println(message)
	m := c.signMessage(message)
	// m.message = []byte("FORGERY!")

	ch<- m
	m =<-ch

	if m.ak {
		fmt.Println("Transaction completed")
	} else {
		fmt.Println("Transaction failed")
	}
}

func createValidMessage(ch chan Message, c Client) Message {
	message := fmt.Sprintf("from=%s&to=%s&amount=%s", "target", "someone", "100")
	m := c.signMessage(message)
	ch<-m
	<-ch

	return m
}

func forgeMessage(ch chan Message, m Message) {

	new_message := []byte("from=vic&to=me&&")

	utils.FixedXORBuffer(m.iv, m.iv, m.message[:16])
	utils.FixedXORBuffer(m.iv, m.iv, new_message)

	// Replace first block with whatever contents we want
	copy(m.message[:16], new_message)

	ch<- m
	<-ch
}

func main() {
	ch := make(chan Message)
	key := utils.GenKey(16)
	// s := new(Server)
	var s Server
	s.key = key
	// c := new(Client)
	var c Client
	c.key = key

	go runServer(ch, s)
	// runClient(ch, c)
	m := createValidMessage(ch, c)
	forgeMessage(ch, m)
}
