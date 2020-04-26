package noncestore

import (
	"fmt"

	"github.com/cblomart/ACMECA/noncestore/memory"

	log "github.com/sirupsen/logrus"
)

const (
	// MemoryStore stores nonces in memory
	MemoryStore = "memory"
)

// NonceStore is a noncestore
type NonceStore interface {
	// Generic information
	Type() string

	// ValidateNonce validates a nonce
	// once validated the nonce is removed from the store
	ValidateNonce(nonce string) bool
	// RegisterNonce register a provided nonce
	GetNonce() (string, error)
}

// Factory creates a store in function of its type
func Factory(storeType string, args map[string]string) (NonceStore, error) {
	switch storeType {
	case MemoryStore:
		return &memory.Store{}, nil
	default:
		log.Errorf("unknown nonce store type requested: %s", storeType)
		return nil, fmt.Errorf("unknown nonce store type requested: %s", storeType)
	}
}
