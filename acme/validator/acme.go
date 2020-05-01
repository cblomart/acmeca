package validator

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/cblomart/ACMECA/acme/validator/dns"
	"github.com/cblomart/ACMECA/acme/validator/tls"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

// Validate validate an acme challenge
func Validate(domain string, validation string, token string, key string) string {
	// create authorization key
	// deserialize the key
	// get the key from account
	rawkey, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		log.Errorf("validator could not decode key: %s", err)
		return "invalid"
	}
	pubkey, err := x509.ParsePKIXPublicKey(rawkey)
	if err != nil {
		log.Errorf("validator could not parse pkix key: %s", err)
		return "invalid"
	}
	// create the jsonwebkey from decoded key
	jwk := jose.JSONWebKey{Key: pubkey}
	// create
	// get the thumbprint of the key
	rawthumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		log.Errorf("validator could not thumbprint the key: %s", err)
		return "invalid"
	}
	// convert the thumbrpint to base64
	thumb := base64.RawURLEncoding.EncodeToString(rawthumb)
	authkey := fmt.Sprintf("%s.%s", token, thumb)
	log.Infof("auth key: %s", authkey)
	switch validation {
	case "dns-01":
		return dns.Validate(domain, authkey)
	case "http-01":
		return "invalid"
	case "tls-alpn-01":
		return tls.Validate(domain, authkey)
	default:
		return "invalid"
	}
}
