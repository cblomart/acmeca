package dns

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

const (
	timeout  = 60
	interval = 1
)

// Validate validates an acme dns-01 challenge
func Validate(domain string, key string) string {
	record := fmt.Sprintf("_acme-challenge.%s", domain)
	log.Infof("dns-01: validating %s", record)
	h := sha256.Sum256([]byte(key))
	hash := base64.RawURLEncoding.EncodeToString(h[:])
	log.Infof("dns-01: expected value %s", hash)
	res, err := net.LookupTXT(record)
	if err != nil {
		log.Errorf("error resolving %s: %s", record, err)
		return "invalid"
	}
	for _, r := range res {
		if r == hash {
			return "valid"
		}
	}
	return "invalid"
}
