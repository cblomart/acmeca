package cert

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/ca"
	"github.com/cblomart/ACMECA/middlewares/certstore"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

var client = http.Client{}

// CertAccept is the accepted encoding of certificates
const CertAccept = "application/pem-certificate-chain"

// Get gets a certificate
func Get(c *gin.Context) {
	id := c.Param("id")
	if len(id) == 0 {
		log.Errorf("id of the cert needed")
		problem.Malformed(c)
		return
	}
	// get certificate store
	store, err := certstore.Get(c)
	if err != nil {
		log.Errorf("could not get certificate store: %s", err)
		problem.ServerInternal(c)
		return
	}
	log.Infof("getting certitifcate: %s", id)
	cert, err := store.GetCert(id)
	if err != nil {
		log.Errorf("could not get certificate from store: %s", err)
		c.Status(http.StatusNotFound)
		return
	}
	out := &bytes.Buffer{}
	// encode certificate
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: *cert})
	// encode ca certificate
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: store.GetCA().Raw})
	c.Data(http.StatusOK, CertAccept, out.Bytes())
}

// ProxyGet gets a certificate via ca
func ProxyGet(c *gin.Context) {
	id := c.Param("id")
	if len(id) == 0 {
		log.Errorf("id of the cert needed")
		problem.Malformed(c)
		return
	}
	log.Infof("getting certitifcate via CA: %s", id)
	// call ca to issue certificate
	caurl, _, err := ca.GetInfo(c)
	if err != nil {
		log.Errorf("cannot find link to CA: %s", err)
		problem.ServerInternal(c)
		return
	}
	// path to csr to the ca
	url := fmt.Sprintf("%s%s/%s", caurl, ep.CertPath, id)
	// create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("Cannot create request: %s", err)
		problem.ServerInternal(c)
		return
	}
	req.Header.Add("Accept", CertAccept)
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("error to cert request: %s", err)
		if resp.StatusCode == http.StatusNotFound {
			c.Status(http.StatusNotFound)
		} else {
			c.Status(http.StatusInternalServerError)
		}
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Errorf("cert request returned: %s", resp.Status)
		c.Status(http.StatusInternalServerError)
		return
	}
	certchain, err := ioutil.ReadAll(resp.Body)
	if len(certchain) == 0 {
		log.Errorf("cert chain returned is empty")
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(http.StatusOK, CertAccept, certchain)
}

// Delete removes a certificate
func Delete(c *gin.Context) {
	id := c.Param("id")
	if len(id) == 0 {
		log.Errorf("id of the cert needed")
		problem.Malformed(c)
		return
	}
	log.Infof("deleting certitifcate: %s", id)
	log.Error("not implemented")
	c.Status(http.StatusNotImplemented)
}
