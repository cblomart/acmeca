package memory

import (
	"sync"

	"github.com/cblomart/ACMECA/noncestore/utils"
)

// Store stores ACME objects in memory
type Store struct {
	nonces   []string
	noncemux sync.Mutex
}

// Type returns the storage type
func (s *Store) Type() string {
	return "memory"
}

// ValidateNonce indicates if a nonce is valid then removes it from the store
func (s *Store) ValidateNonce(nonce string) bool {
	s.noncemux.Lock()
	defer s.noncemux.Unlock()
	i := -1
	for j, n := range s.nonces {
		if n == nonce {
			i = j
			break
		}
	}
	if i >= 0 {
		// if element found remove
		s.nonces[i] = s.nonces[len(s.nonces)-1]
		s.nonces = s.nonces[:len(s.nonces)-1]
		// validate nonce
		return true
	}
	return false
}

// GetNonce generates a new nonce
func (s *Store) GetNonce() (string, error) {
	nonce, err := utils.GenerateNonce()
	if err != nil {
		return "", err
	}
	s.noncemux.Lock()
	defer s.noncemux.Unlock()
	if s.nonces == nil {
		s.nonces = make([]string, 1)
		s.nonces[0] = nonce
	} else {
		s.nonces = append(s.nonces, nonce)
	}
	return nonce, nil
}
