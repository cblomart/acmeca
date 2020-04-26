package file

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// Store represent a storage of certificates
type Store struct {
	path    string
	CA      x509.Certificate
	certmux sync.Mutex
}

// Type returns the storage type
func (s *Store) Type() string {
	return "file"
}

// Init initalize the store
func (s *Store) Init(opts map[string]string) error {
	infos, _ := json.Marshal(opts)
	log.Infof("Init file cert store with opts: %s", infos)
	s.path = "/etc/acmeca/certs"
	if p, ok := opts["path"]; ok {
		s.path = strings.TrimRight(p, "/")
		log.Infof("set path from options: %s", s.path)
	}
	// check if destination exists
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		// try to create folder
		err := os.MkdirAll(s.path, 0770)
		if err != nil {
			return fmt.Errorf("cannot create certificate store: %s", s.path)
		}
	}
	return nil
}

// GetCA gets the CA certificate
func (s *Store) GetCA() *x509.Certificate {
	return &s.CA
}

// GetCert gets a certificate
func (s *Store) GetCert(id string) (*[]byte, error) {
	// path to read
	path := fmt.Sprintf("%s/%s.crt", s.path, id)
	// lock cert directory
	s.certmux.Lock()
	defer s.certmux.Unlock()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate does not exist: %s", s.path)
	}
	// read cert file
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %s", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty certificate: %s", err)
	}
	block, _ := pem.Decode(b)
	return &block.Bytes, nil
}

// DelCert deletes a certificate
func (s *Store) DelCert(id string) error {
	// path to read
	path := fmt.Sprintf("%s/%s.crt", s.path, id)
	// lock cert directory
	s.certmux.Lock()
	defer s.certmux.Unlock()
	err := os.Remove(path)
	if err != nil {
		return fmt.Errorf("cannot delete certificate: %s", err)
	}
	return nil
}

// AddCert adds a certicate
func (s *Store) AddCert(raw *[]byte) error {
	// get the hash of the cert
	hash := md5.Sum(*raw)
	thumbprint := base64.RawURLEncoding.EncodeToString(hash[:])
	// lock folder
	s.certmux.Lock()
	defer s.certmux.Unlock()
	// create cert file
	f, err := os.Create(fmt.Sprintf("%s/%s.crt", s.path, thumbprint))
	if err != nil {
		return fmt.Errorf("could not create certificate file: %s", err)
	}
	defer f.Close()
	// encode certificate
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: *raw})
	if err != nil {
		return fmt.Errorf("could not create certificate file: %s", err)
	}
	return nil
}
