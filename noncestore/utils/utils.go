package utils

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateNonce generates a nonce
func GenerateNonce() (string, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
