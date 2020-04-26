package utils

import (
	//"crypto/sha256"
	//"encoding/base64"

	"github.com/rs/xid"
)

/*
// ID generates an id from a value
func ID(b []byte) string {
	h := sha256.Sum224(b)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
*/

// ID generates an id for a value
func ID() string {
	return xid.New().String()
}
