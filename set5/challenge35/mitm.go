package main

import (
	"fmt"
	"math/big"
	"os"

	"cryptopals/utils"
)

type Server struct {
	dh utils.DH_t
	client_cert, key *big.Int
	aes_key []byte
}

type MessageType int

const (
	NEG MessageType = iota
	ACK
	NACK
	CERT
	MSG
)

func (t MessageType) String() string {
	switch t {
	case NEG:
		return "NEG"
	case ACK:
		return "ACK"
	case NACK:
		return "NACK"
	case CERT:
		return "CERT"
	case MSG:
		return "MSG"
	}
	return "Unknown type"
}

type Message struct {
	msg_type MessageType
	g, p *big.Int
	cert *big.Int
	msg, iv []byte
}

func do_server(c chan Message) {
	var server Server
	for {
		message := <- c
		switch message.msg_type {
		case NEG:
			fmt.Println("S: Received negotiate, accepting")
			server.dh = utils.InitNewDH(message.p, message.g)
			c <- Message{msg_type: ACK}
			continue
		case CERT:
			fmt.Println("S: Received cert")
			server.client_cert = message.cert
			server.key = utils.DHSecret(server.dh, message.cert)
			server.aes_key = utils.SHA1(server.key.Bytes())[:16]
			c <- Message{msg_type: CERT, cert: server.dh.Public}
			continue
		case MSG:
			decoded := utils.AesCbcDecrypt(message.msg, server.aes_key, message.iv)
			// fmt.Printf("S: Raw message: %q\n", decoded)
			var err error
			decoded, err = utils.CheckAndStripPKCS7(decoded)
			if err != nil {
				fmt.Printf("S: Error removing padding: %s\n", err.Error())
			}
			fmt.Printf("S: Received message:\n\t%q\n", decoded)
			response := []byte(fmt.Sprintf("Reponse: %s", decoded))
			response = utils.PKCS7(response, 16)
			iv := utils.GenKey(16)
			echo_message := utils.AesCbcEncrypt(response, server.aes_key, iv)
			c <- Message{msg_type: MSG, msg: echo_message, iv: iv}
			continue
		}
	}
}

var decode_message func([]byte, []byte, *big.Int) []byte
var malicious_g func(*big.Int) *big.Int

func init() {
	if len(os.Args) != 2 {
		fmt.Println("Please specify malicious G val to use")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "1":
		fmt.Printf("Using malicious g val of 1\n")
		malicious_g = malicious_g_1
		decode_message = decode_message_1
	case "p":
		fmt.Printf("Using malicious g val of p\n")
		malicious_g = malicious_g_p
		decode_message = decode_message_p
	case "p-1":
		fmt.Printf("Using malicious g val of p - 1\n")
		malicious_g = malicious_g_p_minus_1
		decode_message = decode_message_p_minus_1
	default:
		fmt.Printf("Invalid G param %s\n", os.Args[1])
		os.Exit(1)
	}

}

func malicious_g_1(p *big.Int) *big.Int {
	return big.NewInt(1)
}

func decode_message_1(data, iv []byte, p *big.Int) []byte {
	aes_key := utils.SHA1(big.NewInt(1).Bytes())[:16]
	return decrypt(data, aes_key, iv)
}

func malicious_g_p(p *big.Int) *big.Int {
	return p
}

func decode_message_p(data, iv []byte, p *big.Int) []byte {
	aes_key := utils.SHA1(big.NewInt(0).Bytes())[:16]
	return decrypt(data, aes_key, iv)
}

func malicious_g_p_minus_1(p *big.Int) *big.Int {
	return new(big.Int).Sub(p, big.NewInt(1))
}

func decode_message_p_minus_1(data, iv []byte, p *big.Int) []byte {
	var key, decoded []byte
	key = utils.SHA1(big.NewInt(1).Bytes())[:16]
	decoded = decrypt(data, key, iv)

	if decoded == nil {
		fmt.Println("Second opinion")
		key = utils.SHA1(new(big.Int).Sub(p, big.NewInt(1)).Bytes())[:16]
		decoded = decrypt(data, key, iv)
	}
	return decoded
}

func decrypt(data, key, iv []byte) []byte {
	decoded := utils.AesCbcDecrypt(data, key, iv)
	decoded_, e := utils.CheckAndStripPKCS7(decoded)
	if e != nil {
		fmt.Println(e.Error())
	}
	return decoded_
}

func mitm(client chan Message) {
	var mitm_data utils.DH_t
	server := make(chan Message)
	go do_server(server)

	for {
		message := <- client
		fmt.Printf("M: Intercepted message C -> S, type %s\n", message.msg_type)
		switch message.msg_type {
		case NEG:
			if message.g.Cmp(malicious_g(message.p)) != 0 {
				fmt.Printf("M: Intercepted NEG, sending NACK with mailicious params\n")
				client <- Message{msg_type: NACK, p: message.p, g: malicious_g(message.p)}
			} else {
				fmt.Printf("M: Intercepted NEG with bad g, passing through\n")
				mitm_data.G = message.g
				mitm_data.P = message.p
				server <- message
				client <- <- server
			}
		case MSG:
			fmt.Printf("M: Intercepted MSG, decoding...\n")


			fmt.Printf("M: Decoded Message: %q\n", decode_message(message.msg, message.iv, mitm_data.P))
			server <- message
			message = <- server
			fmt.Printf("M: Intercepted response MSG, decoding...\n")
			fmt.Printf("M: Decoded Message: %q\n", decode_message(message.msg, message.iv, mitm_data.P))
			client <- message
		default:
			server <- message
			message = <- server
			fmt.Printf("M: Intercepted message S -> C, type %s\n", message.msg_type)
			client <- message
		}
	}
}

func main() {
	c := make(chan Message)
	// go do_server(c)
	go mitm(c)

	var msg Message
	client := utils.InitNewDH(utils.P, utils.G)
	fmt.Printf("C: Sending negotiate\n")
	c <- Message{msg_type: NEG, p: client.P, g: client.G}

	msg = <- c //should be ACK

	for msg.msg_type == NACK {
		fmt.Printf("C: Received NACK, resending NEG\n")
		client = utils.InitNewDH(msg.p, msg.g)
		c <- Message{msg_type: NEG, p: msg.p, g: msg.g}
		msg = <- c
	}

	fmt.Printf("C: Received ACK, sending CERT\n")
	c <- Message{msg_type: CERT, cert: client.Public}

	msg = <- c //should be CERT

	fmt.Printf("C: Received CERT, sending message\n")

	server_cert := msg.cert
	secret := utils.DHSecret(client, server_cert)
	aes_key := utils.SHA1(secret.Bytes())[:16]

	iv := utils.GenKey(16)
	message := utils.AesCbcEncrypt(utils.PKCS7([]byte("Hello, this is a message"), 16), aes_key, iv)

	c <- Message{msg_type: MSG, msg: message, iv: iv}
	msg = <- c

	decoded := utils.AesCbcDecrypt(msg.msg, aes_key, msg.iv)
	decoded, _ = utils.CheckAndStripPKCS7(decoded)
	fmt.Printf("C: Received echo:\n\t%q\n", decoded)
}