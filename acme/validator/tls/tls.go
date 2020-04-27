package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

//ACMETLS1Protocol is the name of the alpn protocol to negociate
const ACMETLS1Protocol = "acme-tls/1"

// Validate validates an acme tls-alpn-01 challenge
func Validate(domain string, key string) string {
	// server to connect to
	server := fmt.Sprintf("%s:443", domain)
	// tls configuration
	tlsConfig := &tls.Config{
		ServerName:         domain,
		NextProtos:         []string{ACMETLS1Protocol},
		InsecureSkipVerify: true,
	}
	// connect to the server
	conn, err := tls.Dial("tcp", server, tlsConfig)
	defer conn.Close()
	if err != nil {
		log.Errorf("could not connect to server %s: %s", domain, err)
		return "invalid"
	}
	cs := conn.ConnectionState()
	if !cs.NegotiatedProtocolIsMutual || cs.NegotiatedProtocol != ACMETLS1Protocol {
		log.Errorf("could not negotiate ALPN protocol %s with %s", ACMETLS1Protocol, domain)
		return "invalid"
	}
	if len(cs.PeerCertificates) == 0 {
		log.Errorf("ssl negociated but no peer certificate")
		return "invalid"
	}
	// check cert
	cert := cs.PeerCertificates[0]
	// check subject alternative names
	count := len(cert.DNSNames)
	if count == 0 {
		log.Errorf("no alterntive names provided")
		return "invalid"
	}
	if count > 1 {
		log.Errorf("more than one alternativeName provided")
		return "invalid"
	}
	dnsname := cert.DNSNames[0]
	if strings.ToLower(domain) != strings.ToLower(dnsname) {
		log.Errorf("alternativeName provided does not correspond to challenge")
		return "invalid"
	}
	// hash to validate in the certificate
	h := sha256.Sum256([]byte(key))
	hash := base64.RawURLEncoding.EncodeToString(h[:])
	log.Infof("expected value: %s", hash)
	// check extension
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Critical && ext.Id.String() == "1.3.6.1.5.5.7.1.31" {
			raw = ext.Value
			break
		}
	}
	// check that acmeIdentifier was found
	if len(raw) == 0 {
		log.Errorf("acmeIdentifier not present")
		return "invalid"
	}
	var value []byte
	_, err = asn1.Unmarshal(raw, &value)
	if err != nil {
		log.Errorf("cannot unmarshall acmeIdentifier value")
		return "invalid"
	}
	base64val := base64.RawURLEncoding.EncodeToString(value)
	log.Infof("recieved value: %s", base64val)
	if hash != base64val {
		log.Errorf("acme identifier didn't have the expected value")
		return "invalid"
	}
	return "valid"
}
