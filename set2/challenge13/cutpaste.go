package main

import (
	"cryptopals/utils"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func init() {
	rand.Seed(int64(time.Now().Nanosecond()))
	theKey = utils.GenKey(16)
}

func parseKV(s string) map[string]string {
	r := make(map[string]string)
	pairs := strings.Split(s, "&")

	for _, s := range pairs {
		kv := strings.Split(s, "=")
		r[kv[0]] = kv[1]
	}

	return r

}

var theKey []byte

func getEncryptedProfile(email string) []byte {
	profile := []byte(profileFor(email))
	profile = utils.PKCS7(profile, 16)

	return utils.AesEcbEncrypt(profile, theKey)
}

func decryptAndParse(s []byte) {
	profileString := string(utils.AesEcbDecrypt(s, theKey))

	profile := parseKV(profileString)

	fmt.Printf("%q\n ", profile)

	if profile["role"] == "admin" {
		fmt.Printf("Success! (key: %s)\n", hex.EncodeToString(theKey))
	}
}

func profileFor(email string) string {
	email = strings.NewReplacer("&", "_", "=", "_").Replace(email)

	return fmt.Sprintf("%s%s%s", "email=", email, "&uid=10&role=user")
}

func main() {

	//                   want this block
	//                  |--------------|
	// email=abcdefghij admin&uid=10&rol e=user
	// 0123456789abcdef 0123456789abcdef 012345

	codeBlockStartWithAdmin := getEncryptedProfile("abcdefghijadmin")[16:32]

	//          want these blocks
	// |-------------------------------|
	// email=abcdefghij klm&uid=10&role= user
	// 0123456789abcdef 0123456789abcdef 0123

	codeBlocksEndingWithRole := getEncryptedProfile("abcdefghijklm")[0:32]

	//                                  want this
	//                                   |---->
	// email=abcdefghij klmn&uid=10&role =user
	// 0123456789abcdef 0123456789abcdef 0123

	lastCodeBlock := getEncryptedProfile("abcdefghijklmn")[32:]

	// Should end up looking like this:
	//
	//    codeBlocksEndingWithRole        startWithAdmin   lastCodeBlock
	// |-------------------------------| |--------------| |---> (padding)
	// email=abcdefghij klm&uid=10&role= admin&uid=10&rol =user
	// 0123456789abcdef 0123456789abcdef 0123456789abcdef 01234
	//
	// Note: success depends on parsing function accepting sprurious 'rol' key

	craftedCode := append(append(codeBlocksEndingWithRole, codeBlockStartWithAdmin...), lastCodeBlock...)

	fmt.Println(hex.EncodeToString(craftedCode))

	decryptAndParse(craftedCode)
}
