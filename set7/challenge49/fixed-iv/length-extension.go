package main

import (
	"bytes"
	"fmt"
	"strings"

	"cryptopals/utils"
)

var ZERO_IV = make([]byte, 16)

type Message struct {
	message, mac []byte
	ak bool
}

type Server struct {
	key []byte
}

type Client struct {
	key []byte
}

func (s Server) validateMessage(m Message) bool {
	data := utils.AesCbcEncrypt(utils.PKCS7(m.message, 16), s.key, ZERO_IV)
	calculated := data[len(data) - 16:]

	if bytes.Equal(calculated, m.mac) {
		return true
	} else {
		return false
	}
}

func (c Client) signMessage(m string) Message {
	mb := []byte(m)

	data := utils.AesCbcEncrypt(utils.PKCS7(mb, 16), c.key, ZERO_IV)
	mac := data[len(data) - 16:]

	return Message{mb, mac, false}
}

type transaction struct{
	to, amount string
}

func parseTransactionList(list string) []transaction {
	transactions := make([]transaction, 0)

	for _, tx := range(strings.Split(list, ";")) {
		to_amount_pair := strings.Split(tx, ":")
		if len(to_amount_pair) != 2 {
			fmt.Println("Error parsing transaction list")
			continue
		}
		transactions = append(transactions, transaction{to_amount_pair[0], to_amount_pair[1]})
	}

	return transactions
}

// This function needs to be deliberately lenient for the attack to work
func parseMessage(m []byte) {
	s := string(m)
	parts := strings.Split(s, "&")

	var from string
	var transactions []transaction

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
		case "tx_list":
			transactions = parseTransactionList(val)
		}
	}
	if from == "" || len(transactions) == 0 {
		printRed("Wrong message format")
	} else {
		fmt.Printf("Transferring from %s\n", from)
		for _, tx := range(transactions) {
			fmt.Printf("\t%s to %s\n", tx.amount, tx.to)
		}
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

func main() {
	key := utils.GenKey(16)
	server := Server{key}

	ch := make(chan Message)

	go runServer(ch, server)

	client := Client{key}

	// first intercept a valid tx from target
	valid_message_string := "from=target&tx_list=targets_friend:1000;another:500"
	intercepted_message := client.signMessage(valid_message_string)
	ch <- intercepted_message
	<-ch

	// create our own message
	// assume we can intercept this (prevent it reaching server) or that
	// there is no problem if this tx occurs
	our_message_string := "from=us&tx_list=dummy:0;us:10000000"
	our_message := client.signMessage(our_message_string)
	ch <- our_message
	<- ch

	// first, pad the intercepted message
	forged_string := utils.PKCS7(intercepted_message.message, 16)

	//convert our message to bytes
	our_bytes := []byte(our_message_string)

	// XOR the CBC-MAC of the intercepted message with the first block of
	// our own message
	utils.FixedXORBuffer(our_bytes[:16],
		our_bytes[:16],
		intercepted_message.mac)

	// append our string to the forged message, the resulting CBC-MAC will be
	// the same as that for our own legit message
	forged_string = append(forged_string, our_bytes...)
	forged_message := Message{forged_string, our_message.mac, false}
	ch<- forged_message
	<-ch
}
