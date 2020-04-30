package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cblomart/ACMECA/acme/ep"
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

func writeKey(file string, key *rsa.PrivateKey) {
	out := &bytes.Buffer{}
	// encode key
	pemBlock, err := pemBlockForKey(key)
	if err != nil {
		log.Fatalf("error serializing key: %v", err)
	}
	pem.Encode(out, pemBlock)
	f, err := os.Create(file)
	if err != nil {
		log.Fatalf("Could not create key file: %v", err)
	}
	_, err = out.WriteTo(f)
	if err != nil {
		log.Fatalf("Could not write to key file: %s", err)
	}
	f.Close()
}

func generatetls(httpscert, httpskey, hostnames, parentcert, parentkey string, ca bool) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	//priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	writeKey(httpskey, key)
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
	if len(parentcert) == 0 {
		return
	}
	// encode ca certificate
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: parent.Raw})
	_, err = out.WriteTo(f)
	if err != nil {
		log.Fatalf("could not write ca to certificate file: %s", err)
	}
	f.Close()
}

func waitca(caurl string, wait, count int) {
	client := http.Client{}
	url := fmt.Sprintf("%s/%s", caurl, ep.HealthPath)
	for count >= 0 {
		resp, _ := client.Head(url)
		if resp.StatusCode == http.StatusOK {
			return
		}
		count = count - 1
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

func requesttls(httpscert, httpskey, hostnames, caurl, secret string) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	//priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	writeKey(httpskey, key)
	dnsnames := strings.Split(hostnames, ",")
	if len(dnsnames) == 0 {
		log.Fatal("no dns names provided")
	}
	subj := pkix.Name{
		CommonName:   dnsnames[0],
		Organization: []string{"Acme CA"},
	}
	asn1Subj, err := asn1.Marshal(subj.ToRDNSequence())
	if err != nil {
		log.Fatal(err)
	}
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		DNSNames:           dnsnames,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		log.Fatal(err)
	}
	// wait for CA
	waitca(caurl, 5, 60)
	// submit csr to ca
	// encoding csr bytes
	csrtxt := base64.StdEncoding.EncodeToString(csr)
	// path to csr to the ca
	url := fmt.Sprintf("%s%s", caurl, ep.CsrPath)
	// authentication
	auth := fmt.Sprintf("Bearer %s", base64.RawURLEncoding.EncodeToString([]byte(secret)))
	// create the request
	req, err := http.NewRequest("POST", url, strings.NewReader(csrtxt))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Authorization", auth)
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		log.Fatal("ca server didn't create certificate")
	}
	certurl := resp.Header.Get("Location")
	if len(certurl) == 0 {
		log.Fatal("ca server created the certificate but no location")
	}
	// create the request
	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Cannot create request: %s", err)
	}
	req.Header.Add("Accept", "application/pem-certificate-chain")
	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("cert request returned: %s", resp.Status)
	}
	certchain, err := ioutil.ReadAll(resp.Body)
	if len(certchain) == 0 {
		log.Fatal("cert chain returned is empty")
	}
	f, err := os.Create(httpscert)
	if err != nil {
		log.Fatalf("Could not create cert file: %v", err)
	}
	_, err = f.Write(certchain)
	if err != nil {
		log.Fatalf("Could not write to cert file: %s", err)
	}
	f.Close()
}
