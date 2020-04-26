package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	keySize = 4096
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, fmt.Errorf("Unknown private key format")
	}
}

func keyForPemBlock(pem *pem.Block) (interface{}, error) {
	switch pem.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(pem.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(pem.Bytes)
	default:
		return nil, fmt.Errorf("Unknonw private key format")
	}
}

func readCert(certfile string) (*x509.Certificate, error) {
	// read parent certificate
	b, err := ioutil.ReadFile(certfile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read certificate: %s", err)
	}
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err)
	}
	return cert, nil
}

func readKey(keyfile string) (interface{}, error) {
	// read parent key
	b, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read parent key: %s", err)
	}
	block, _ := pem.Decode(b)
	key, err := keyForPemBlock(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode parent key: %s", err)
	}
	return key, nil
}

func generatetls(httpscert, httpskey, hostnames, parentcert, parentkey string, ca bool) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	//priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	dnsnames := strings.Split(hostnames, ",")
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 8*20))
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Acme CA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 30 * 6),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if len(dnsnames) > 0 {
		template.Subject.CommonName = dnsnames[0]
		template.DNSNames = dnsnames
	}
	if ca {
		template.IsCA = true
		template.NotAfter = time.Now().Add(time.Hour * 24 * 30 * 36)
		template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
	}
	pub := publicKey(key)
	var priv interface{}
	priv = key
	parent := &template
	if checkFile(parentcert) && checkFile(parentkey) {
		parent, err = readCert(parentcert)
		if err != nil {
			log.Fatal(err)
			return
		}
		// read parent key
		priv, err = readKey(parentkey)
		if err != nil {
			log.Fatal(err)
			return
		}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, pub, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	// encode certificate
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	f, err := os.Create(httpscert)
	if err != nil {
		log.Fatalf("could not create certificate file: %s", err)
	}
	_, err = out.WriteTo(f)
	if err != nil {
		log.Fatalf("could not write to certificate file: %s", err)
	}
	f.Close()
	out.Reset()
	// encode key
	pemBlock, err := pemBlockForKey(key)
	if err != nil {
		log.Fatalf("error serializing key: %v", err)
	}
	pem.Encode(out, pemBlock)
	f, err = os.Create(httpskey)
	if err != nil {
		log.Fatalf("Could not create key file: %v", err)
	}
	_, err = out.WriteTo(f)
	if err != nil {
		log.Fatalf("Could not write to key file: %s", err)
	}
	f.Close()
}
