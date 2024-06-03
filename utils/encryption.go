// Borrowed from: https://github.com/Ry0taK/SmartDeviceAggregator/blob/main/pkg/utils/encryption.go
package utils

import (
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"log"
	"strings"
	"time"

	"github.com/elliotchance/orderedmap/v2"
)

type RC4Decrypter struct {
	cipher *rc4.Cipher
}

func GenerateNonce() []byte {
	randBytes := make([]byte, 8)
	_, err := rand.Read(randBytes)
	if err != nil {
		log.Fatalf("failed to generate random bytes: %v", err)
	}

	currentTimeInMillisecondsBytes := make([]byte, 4)
	currentTimeInMilliseconds := time.Now().UnixMilli()
	binary.BigEndian.PutUint32(currentTimeInMillisecondsBytes, uint32(currentTimeInMilliseconds/60000))

	nonce := append(randBytes, currentTimeInMillisecondsBytes...)
	return nonce
}

func CalculateRC4Key(ssecurity []byte, nonce []byte) []byte {
	rc4Key := append(ssecurity, nonce...)
	hasher := sha256.New()
	hasher.Write(rc4Key)
	rc4KeyHashed := hasher.Sum(nil)
	return rc4KeyHashed
}

func NewRC4Decrypter(rc4Key []byte) *RC4Decrypter {
	cipher, err := rc4.NewCipher(rc4Key)
	if err != nil {
		// This error should never happen
		panic(err)
	}
	dropBytes := make([]byte, 1024)
	cipher.XORKeyStream(dropBytes, []byte(dropBytes))
	return &RC4Decrypter{cipher: cipher}
}

// WIP change it to receive a byte slice
func (d *RC4Decrypter) Decrypt(encrypted string) (string, error) {
	encryptedDecoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	decrypted := make([]byte, len(encryptedDecoded))

	d.cipher.XORKeyStream(decrypted, encryptedDecoded)
	return string(decrypted), nil
}

func (d *RC4Decrypter) Encrypt(stringToEncrypt []byte) []byte {
	encrypted := make([]byte, len(stringToEncrypt))
	d.cipher.XORKeyStream(encrypted, stringToEncrypt)
	return encrypted
}

func CalculateSignature(method, path string, rc4Key []byte, params *orderedmap.OrderedMap[string, string]) string {
	rc4KeyEncoded := base64.StdEncoding.EncodeToString(rc4Key)
	parts := []string{}
	if method != "" {
		parts = append(parts, strings.ToUpper(method))
	}
	if path != "" {
		parts = append(parts, path)
	}
	if params.Len() > 0 {
		for _, key := range params.Keys() {
			value := params.GetOrDefault(key, "")
			parts = append(parts, key+"="+value)
		}
	}
	parts = append(parts, rc4KeyEncoded)

	signature := strings.Join(parts, "&")

	hasher := sha1.New()
	hasher.Write([]byte(signature))
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}
