package main

import (
	"fmt"
	"math/big"
	"cryptopals/utils"
)

var client, server utils.DH_t

var server_saved_A, server_saved_Key *big.Int

var client_saved_B, client_saved_Key *big.Int

func init_echo(p, g, A *big.Int) *big.Int {
	server = utils.InitNewDH(p, g)
	server_saved_A = A
	server_saved_Key = utils.DHSecret(server, A)

	return server.Public
}

func echo(message, iv []byte) ([]byte, []byte) {
	key := utils.SHA1(server_saved_Key.Bytes())[:16]
	decoded := utils.AesCbcDecrypt(message, key, iv)
	decoded, _ = utils.CheckAndStripPKCS7(decoded)
	fmt.Printf("S: message received: %q\n", decoded)
	response := []byte(fmt.Sprintf("Reponse: %s", decoded))

	new_iv := utils.GenKey(16)

	return utils.AesCbcEncrypt(utils.PKCS7(response, 16), key, new_iv), new_iv
}

func init_echo_mitm(p, g, A *big.Int) *big.Int {
	fmt.Println("M: Intercepted setup")
	init_echo(p, g, p)
	return p
}

func echo_mitm(message, iv []byte) ([]byte, []byte) {
	fmt.Println("M: Intercepted message, decrypting")
	// key is 0, so get big.Int bytes for 0 and hash for AES key
	key := utils.SHA1(big.NewInt(0).Bytes())[:16]
	decrypted := utils.AesCbcDecrypt(message, key, iv)
	decrypted, _ = utils.CheckAndStripPKCS7(decrypted)
	fmt.Printf("M: message is %q\n", decrypted)
	
	response, response_iv := echo(message, iv)
	decrypted = utils.AesCbcDecrypt(response, key, response_iv)
	decrypted, _ = utils.CheckAndStripPKCS7(decrypted)
	fmt.Printf("M: message from server is %q\n", decrypted)

	return response, response_iv
}

func main() {
	client = utils.InitNewDH(utils.P, utils.G)
	client_saved_B = init_echo_mitm(client.P, client.G, client.Public)
	client_saved_Key = utils.DHSecret(client, client_saved_B)

	key := utils.SHA1(client_saved_Key.Bytes())[:16]
	iv := utils.GenKey(16)

	message := utils.AesCbcEncrypt(utils.PKCS7([]byte("Hello, this is a banana"), 16), key, iv)

	response, response_iv := echo_mitm(message, iv)

	decoded := utils.AesCbcDecrypt(response, key, response_iv)
	decoded, _ = utils.CheckAndStripPKCS7(decoded)
	fmt.Printf("C: response received: %q\n", decoded)
}