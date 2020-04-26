package file

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
)

// Store represent a storage of certificates
type Store struct {
	Path    string
	CA      x509.Certificate
	certs   []x509.Certificate
	certmux sync.Mutex
}

// Type returns the storage type
func (s *Store) Type() string {
	return "memory"
}

// GetCA gets the CA certificate
func (s *Store) GetCA() *x509.Certificate {
	return &s.CA
}

// GetCert gets a certificate
func (s *Store) GetCert(id string) (*[]byte, error) {
	s.certmux.Lock()
	defer s.certmux.Unlock()
	for _, cert := range s.certs {
		hash := md5.Sum(cert.Raw)
		sign := base64.RawURLEncoding.EncodeToString(hash[:])
		if sign == id {
			return &cert.Raw, nil
		}
	}
	return nil, fmt.Errorf("Certificate not found: %s", id)
}

// DelCert deletes a certificate
func (s *Store) DelCert(id string) error {
	s.certmux.Lock()
	defer s.certmux.Unlock()
	found := -1
	for i, cert := range s.certs {
		hash := md5.Sum(cert.Raw)
		sign := base64.RawURLEncoding.EncodeToString(hash[:])
		if sign == id {
			found = i
		}
	}
	if found < 0 {
		return fmt.Errorf("Certificate not found: %s", id)
	}
	s.certs[found] = s.certs[len(s.certs)-1]
	s.certs = s.certs[:len(s.certs)-1]
	return nil
}

// AddCert adds a certicate
func (s *Store) AddCert(raw *[]byte) error {
	cert, err := x509.ParseCertificate(*raw)
	if err != nil {
		return fmt.Errorf("cannot parse cert: %s", err)
	}
	s.certmux.Lock()
	defer s.certmux.Unlock()
	s.certs = append(s.certs, *cert)
	return nil
}
