package certstore

import (
	"crypto/x509"
	"fmt"

	"github.com/cblomart/ACMECA/certstore/file"
	"github.com/cblomart/ACMECA/certstore/memory"

	log "github.com/sirupsen/logrus"
)

const (
	// MemoryStore stores certs in memory
	MemoryStore = "memory"
	// FileStore stores certs in a folder
	FileStore = "file"
)

// CertStore is a noncestore
type CertStore interface {
	// Generic information
	Type() string
	Init(opts map[string]string) error

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
	var store CertStore
	switch storeType {
	case MemoryStore:
		store = &memory.Store{CA: *cacert}
	case FileStore:
		store = &file.Store{CA: *cacert}
	default:
		log.Errorf("unknown certificate store type requested: %s", storeType)
		return nil, fmt.Errorf("unknown certificate store type requested: %s", storeType)
	}
	err := store.Init(args)
	if err != nil {
		return nil, fmt.Errorf("cannot create '%s' cert store: %s", storeType, err)
	}
	return store, nil
}
