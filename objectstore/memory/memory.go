package memory

import (
	"sync"

	"github.com/cblomart/ACMECA/objectstore/objects"
)

// Store stores ACME objects in memory
type Store struct {
	accounts   []objects.Account
	accmux     sync.Mutex
	orders     []objects.Order
	ordmux     sync.Mutex
	authzs     []objects.Authorization
	authzmux   sync.Mutex
	challenges []objects.Challenge
	chamux     sync.Mutex
}

// Type returns the storage type
func (s *Store) Type() string {
	return "memory"
}

// Init initializes a memory storage
func (s *Store) Init(opts map[string]string) error {
	return nil
}
