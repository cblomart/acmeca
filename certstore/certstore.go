package certstore

import (
	"crypto/x509"
	"fmt"

	"github.com/cblomart/ACMECA/certstore/memory"

	log "github.com/sirupsen/logrus"
)

const (
	// MemoryStore stores nonces in memory
	MemoryStore = "memory"
)

// CertStore is a noncestore
type CertStore interface {
	// Generic information
	Type() string

	// Get CA
	GetCA() *x509.Certificate

	// GetCert gets a certificate
	GetCert(id string) (*[]byte, error)
	// DelCert removes a certificate
	DelCert(id string) error
	AddCert(raw *[]byte) error
}

// Factory creates a store in function of its type
func Factory(storeType string, cacert *x509.Certificate, args map[string]string) (CertStore, error) {
	switch storeType {
	case MemoryStore:
		return &memory.Store{CA: *cacert}, nil
	default:
		log.Errorf("unknown certificate store type requested: %s", storeType)
		return nil, fmt.Errorf("unknown certificate store type requested: %s", storeType)
	}
}
