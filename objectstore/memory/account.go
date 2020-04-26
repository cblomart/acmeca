package memory

import (
	"fmt"

	"github.com/cblomart/ACMECA/objectstore/objects"
	log "github.com/sirupsen/logrus"
)

// GetAccount gets an existing account
func (s *Store) GetAccount(kid string) (*objects.Account, error) {
	s.accmux.Lock()
	defer s.accmux.Unlock()
	i := -1
	for j, a := range s.accounts {
		if a.KeyID == kid {
			i = j
			break
		}
	}
	if i >= 0 {
		return &s.accounts[i], nil
	}
	return nil, nil
}

// GetAccountFromKey gets an existing account from key
func (s *Store) GetAccountFromKey(key string) (*objects.Account, error) {
	s.accmux.Lock()
	defer s.accmux.Unlock()
	i := -1
	for j, a := range s.accounts {
		if a.Key == key {
			i = j
			break
		}
	}
	if i >= 0 {
		return &s.accounts[i], nil
	}
	return nil, nil
}

// CreateAccount creates an account
func (s *Store) CreateAccount(account objects.Account) error {
	if !account.Check() {
		return fmt.Errorf("invalid account")
	}
	account.Status = "valid"
	s.accmux.Lock()
	defer s.accmux.Unlock()
	i := -1
	for j, a := range s.accounts {
		if a.KeyID == account.KeyID {
			i = j
			break
		}
	}
	if i >= 0 {
		return fmt.Errorf("account already exists")
	}
	//TODO: validate contacts
	s.accounts = append(s.accounts, account)
	log.Infof("Account (%d total) - new: %s", len(s.accounts), account.KeyID)
	return nil
}

// UpdateAccount updates an account
func (s *Store) UpdateAccount(account objects.Account) (*objects.Account, error) {
	if !account.Check() {
		return nil, fmt.Errorf("invalid account")
	}
	s.accmux.Lock()
	defer s.accmux.Unlock()
	i := -1
	for j, a := range s.accounts {
		if a.KeyID == account.KeyID {
			i = j
			break
		}
	}
	if i > 0 {
		s.accounts[i].Update(account)
		log.Infof("Account (%d total) - updated: %s", len(s.accounts), s.accounts[i].KeyID)
	}
	return &s.accounts[i], nil
}

// RevokeAccount revokes an account (on admin/server request)
func (s *Store) RevokeAccount(kid string) error {
	s.accmux.Lock()
	defer s.accmux.Unlock()
	i := -1
	for j, a := range s.accounts {
		if a.KeyID == kid {
			i = j
			break
		}
	}
	s.accounts[i].Status = "revoked"
	log.Infof("Account (%d total) - revoked: %s", len(s.accounts), s.accounts[i].KeyID)
	return nil
}

// DeactivateAccount deactivas account (on user request)
func (s *Store) DeactivateAccount(kid string) error {
	s.accmux.Lock()
	defer s.accmux.Unlock()
	i := -1
	for j, a := range s.accounts {
		if a.KeyID == kid {
			i = j
			break
		}
	}
	s.accounts[i].Status = "deactivated"
	log.Infof("Account (%d total) - deactiveted: %s", len(s.accounts), s.accounts[i].KeyID)
	return nil
}
