package csr

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/ca"
	"github.com/cblomart/ACMECA/middlewares/certstore"
	"github.com/cblomart/ACMECA/middlewares/objectstore"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

var client = http.Client{}

// ValidityPeriod is the period of validity of delivered certificates
const ValidityPeriod = time.Hour * 24 * 30 * 3

// Payload represents the payload of a request
type Payload struct {
	CSR string `json:"csr"`
}

// Post handles a post request to order enpoint
func Post(c *gin.Context) {
	// get storage
	store, err := objectstore.Get(c)
	if err != nil {
		log.Errorf("cannot rretrieve store: %s", err)
		problem.ServerInternal(c)
		return
	}
	// check order
	id := c.Param("id")
	if len(id) == 0 {
		log.Errorf("CSR should be called with the reference of an order")
		problem.Malformed(c)
		return
	}
	// get order
	order, err := store.GetOrder(id)
	if err != nil || order == nil {
		log.Errorf("cannot retrieve order: %s", err)
		problem.ServerInternal(c)
		return
	}
	if order.Status != "ready" {
		log.Error("cannot call CSR when order not ready")
		problem.OrderNotReady(c)
		return
	}
	// get the use key id
	var kid string
	if tmp, ok := c.Get("kid"); ok {
		kid = fmt.Sprintf("%s", tmp)
	}
	if len(kid) == 0 {
		log.Error("kid was empty")
		problem.ServerInternal(c)
		return
	}
	// check authorization
	if order.KeyID != kid {
		log.Errorf("not authorized for this order: %s", kid)
		problem.Unauthorized(c)
		return
	}
	//check the the order is ready
	if order.Status != "ready" {
		log.Errorf("request csr from an not ready order")
		problem.Unauthorized(c)
		return
	}
	// check payload
	var payload string
	if tmp, ok := c.Get("payload"); ok {
		payload = fmt.Sprintf("%s", tmp)
	}
	if len(payload) == 0 {
		log.Errorf("Called CSR without a payload")
		problem.BadCSR(c)
		return
	}
	csrReq := &Payload{}
	err = json.Unmarshal([]byte(payload), csrReq)
	if err != nil {
		log.Errorf("cannot read CSR payload: %s", err)
		problem.BadCSR(c)
		return
	}
	// decode csr request
	b, err := base64.RawURLEncoding.DecodeString(csrReq.CSR)
	if err != nil {
		log.Errorf("cannot read CSR base64: %s", err)
		problem.BadCSR(c)
		return
	}
	csr, err := x509.ParseCertificateRequest(b)
	if err != nil {
		log.Errorf("cannot decode CSR: %s", err)
		problem.BadCSR(c)
		return
	}
	// check csr
	// check signature
	err = csr.CheckSignature()
	if err != nil {
		log.Errorf("issue with CSR signature: %s", err)
		problem.BadCSR(c)
		return
	}
	// list validated identifier
	dnsNames := make([]string, len(order.Identitifers))
	for i, identity := range order.Identitifers {
		dnsNames[i] = identity.Value
	}
	sort.Strings(dnsNames)
	// check that the common name is a validated identity
	found := false
	for _, dnsName := range dnsNames {
		if dnsName == csr.Subject.CommonName {
			found = true
			break
		}
	}
	if !found {
		log.Errorf("CommonName not in identities")
		problem.BadCSR(c)
		return
	}
	// check that dns names are equal to dnsNames
	csrNames := make([]string, len(csr.DNSNames))
	copy(csrNames, csr.DNSNames)
	if len(csrNames) != len(dnsNames) {
		log.Errorf("Alternative names does not match identities count")
		problem.BadCSR(c)
		return
	}
	sort.Strings(csrNames)
	for i := 0; i < len(csrNames); i++ {
		if csrNames[i] != dnsNames[i] {
			log.Errorf("Alternative names does not match identities ('%s')", csrNames[i])
			problem.BadCSR(c)
			return
		}
	}
	// check that no other types of alternative names are provided
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 {
		log.Errorf("Alternative names contains mails or IPs")
		problem.BadCSR(c)
		return
	}
	// call ca to issue certificate
	caurl, capass, err := ca.GetInfo(c)
	if err != nil {
		log.Errorf("cannot find link to CA: %s", err)
		problem.ServerInternal(c)
		return
	}
	// encoding csr bytes
	csrtxt := base64.StdEncoding.EncodeToString(csr.Raw)
	// path to csr to the ca
	url := fmt.Sprintf("%s%s", caurl, ep.CsrPath)
	// authentication
	auth := fmt.Sprintf("Bearer %s", base64.RawURLEncoding.EncodeToString([]byte(capass)))
	// create the request
	req, err := http.NewRequest("POST", url, strings.NewReader(csrtxt))
	if err != nil {
		log.Errorf("Cannot create request: %s", err)
		problem.ServerInternal(c)
		return
	}
	req.Header.Add("Authorization", auth)
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("error to csr post request: %s", err)
		c.JSON(http.StatusOK, order)
		return
	}
	if resp.StatusCode != http.StatusCreated {
		log.Errorf("ca server didn't create certificate")
		c.JSON(http.StatusOK, order)
		return
	}
	certurl := resp.Header.Get("Location")
	if len(certurl) == 0 {
		log.Errorf("ca server created the certificate but no location")
		c.JSON(http.StatusOK, order)
		return
	}
	// set certificate url in order
	order.Certificate = certurl
	// set order as valid
	order.Status = "valid"
	store.UpdateOrder(order)
	log.Infof("order %s valid: %s", order.ID, order.Certificate)
	c.JSON(http.StatusOK, order)
}

// CaPost handles a post request to get a certificate from the CA
func CaPost(c *gin.Context) {
	// get signing informations
	rootkey, err := ca.GetSigning(c)
	if err != nil {
		log.Errorf("could not get signing infos: %s", err)
		problem.ServerInternal(c)
		return
	}
	// get certificate store
	store, err := certstore.Get(c)
	if err != nil {
		log.Errorf("could not get certificate store: %s", err)
		problem.ServerInternal(c)
		return
	}
	rootcert := store.GetCA()
	// read request body
	rawcsr, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.Errorf("could not read request body: %s", err)
		problem.ServerInternal(c)
		return
	}
	// decode csr
	csrBytes, err := base64.StdEncoding.DecodeString(string(rawcsr))
	// parse request
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		log.Errorf("could not decode csr: %s", err)
		problem.ServerInternal(c)
		return
	}
	// generate serial
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 8*20))
	if err != nil {
		log.Errorf("could not generate serial: %s", err)
		problem.ServerInternal(c)
		return
	}
	// create client certificate template
	template := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber:          serial,
		Issuer:                rootcert.Subject,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(ValidityPeriod),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// create client certificate from template and CA public key
	clientcert, err := x509.CreateCertificate(rand.Reader, &template, rootcert, csr.PublicKey, rootkey)
	if err != nil {
		log.Errorf("could not generate certificate: %s", err)
		problem.ServerInternal(c)
		return
	}
	store.AddCert(&clientcert)
	// get certificate hash
	crt, err := x509.ParseCertificate(clientcert)
	if err != nil {
		log.Errorf("could not read generated cert: %s", err)
		problem.ServerInternal(c)
		return
	}
	hash := md5.Sum(crt.Raw)
	sign := base64.RawURLEncoding.EncodeToString(hash[:])
	url := location.Get(c).String()
	log.Infof("Generated %s cert for %s", sign, crt.Subject.CommonName)
	c.Header("Location", fmt.Sprintf("%s%s/%s", url, ep.CertPath, sign))
	c.Status(http.StatusCreated)
}
