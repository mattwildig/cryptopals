// MITM Key Fixing attack on Diffiie-Hellman with parameter injection.

package main

import (
	"fmt"
	"math/big"

	"cryptopals/aes"
	"cryptopals/dh"
	"cryptopals/hash/sha1"
	"cryptopals/keys"
)

var client, server dh.Key

var server_saved_A, server_saved_Key *big.Int

var client_saved_B, client_saved_Key *big.Int

func init_echo(p, g, A *big.Int) *big.Int {
	server = dh.InitNew(p, g)
	server_saved_A = A
	server_saved_Key = dh.Secret(server, A)

	return server.Public
}

func echo(message, iv []byte) ([]byte, []byte) {
	key := sha1.Sum(server_saved_Key.Bytes())[:16]
	decoded := aes.CbcDecrypt(message, key, iv)
	decoded, _ = aes.CheckAndStripPKCS7(decoded)
	fmt.Printf("S: message received: %q\n", decoded)
	response := []byte(fmt.Sprintf("Reponse: %s", decoded))

	new_iv := keys.New(16)

	return aes.CbcEncrypt(aes.PKCS7(response, 16), key, new_iv), new_iv
}

func init_echo_mitm(p, g, A *big.Int) *big.Int {
	fmt.Println("M: Intercepted setup")
	init_echo(p, g, p)
	return p
}

func echo_mitm(message, iv []byte) ([]byte, []byte) {
	fmt.Println("M: Intercepted message, decrypting")
	// key is 0, so get big.Int bytes for 0 and hash for AES key
	key := sha1.Sum(big.NewInt(0).Bytes())[:16]
	decrypted := aes.CbcDecrypt(message, key, iv)
	decrypted, _ = aes.CheckAndStripPKCS7(decrypted)
	fmt.Printf("M: message is %q\n", decrypted)
	
	response, response_iv := echo(message, iv)
	decrypted = aes.CbcDecrypt(response, key, response_iv)
	decrypted, _ = aes.CheckAndStripPKCS7(decrypted)
	fmt.Printf("M: message from server is %q\n", decrypted)

	return response, response_iv
}

func main() {
	client = dh.InitNew(dh.P, dh.G)
	client_saved_B = init_echo_mitm(client.P, client.G, client.Public)
	client_saved_Key = dh.Secret(client, client_saved_B)

	key := sha1.Sum(client_saved_Key.Bytes())[:16]
	iv := keys.New(16)

	message := aes.CbcEncrypt(aes.PKCS7([]byte("Hello, this is a banana"), 16), key, iv)

	response, response_iv := echo_mitm(message, iv)

	decoded := aes.CbcDecrypt(response, key, response_iv)
	decoded, _ = aes.CheckAndStripPKCS7(decoded)
	fmt.Printf("C: response received: %q\n", decoded)
}
