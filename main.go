package main

import (
	"encoding/base64"
	"fmt"

	"github.com/bitesizedlion/testmi/utils"
)

var b64ssecurity = "yAZRmgeaxyjQJrCL2TZZIQ==" // replace with ssecurity from login response
var b64nonce = "6PDS0VcJ0SYBtMCR"             // replace with nonce from request, or figure out making all the requests, see utils/encryption.go

func main() {
	ssecurity, err := base64.StdEncoding.DecodeString(b64ssecurity)
	if err != nil {
		fmt.Println("oops: ", err)
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(b64nonce)
	if err != nil {
		fmt.Println("oops 2: ", err)
		return
	}
	rc4Key := utils.CalculateRC4Key(ssecurity, nonce)

	rc4Decryptor := utils.NewRC4Decrypter(rc4Key)

	// your RC4-encrypted data
	decrypted, err := rc4Decryptor.Decrypt("VucWPJE1TQV6CZX+zNLtGm1cVPmQJ8n9gOOrOU4jSqcCMBF3vlUqYc2GzIarTohJjQZYLUfGBvXZ+g4tFnEHvk6ddOZrpf9CyZ3a03mOQcJl/kVEQbj0VhOqS3qCdSKR5xqWsLNGOE0vE0ED6znxTgKOGHw4MKjJlBqfZ9Q=")

	if err != nil {
		fmt.Println("oops 3: ", err)
		return
	}

	print(decrypted)
}
