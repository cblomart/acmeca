package xorm

import (
	"fmt"

	"github.com/cblomart/ACMECA/objectstore/objects"
)

// GetAccount gets an existing account
func (s *Store) GetAccount(kid string) (*objects.Account, error) {
	var account objects.Account
	ok, err := s.engine.Where("keyid = ?", kid).Get(&account)
	if err != nil {
		return nil, fmt.Errorf("couldn't retrieve account %s: %s", kid, err)
	}
	if ok {
		return &account, nil
	}
	return nil, nil
}

// GetAccountFromKey gets an existing account from key
func (s *Store) GetAccountFromKey(key string) (*objects.Account, error) {
	var account objects.Account
	ok, err := s.engine.Where("key = ?", key).Get(&account)
	if err != nil {
		return nil, fmt.Errorf("couldn't retrieve account with specified key: %s", err)
	}
	if ok {
		return &account, nil
	}
	return nil, nil
}

// CreateAccount creates an account
func (s *Store) CreateAccount(account objects.Account) error {
	if !account.Check() {
		return fmt.Errorf("invalid account")
	}
	account.Status = "valid"
	exists, err := s.engine.Where("keyid = ?", account.KeyID).Exist(&objects.Account{})
	if err != nil {
		return fmt.Errorf("error checking for account %s: %s", account.KeyID, err)
	}
	if exists {
		return fmt.Errorf("account already exists")
	}
	s.engine.Insert(account)
	return nil
}

// UpdateAccount updates an account
func (s *Store) UpdateAccount(account objects.Account) (*objects.Account, error) {
	if !account.Check() {
		return nil, fmt.Errorf("invalid account")
	}
	_, err := s.engine.Update(account, objects.Account{KeyID: account.KeyID})
	if err != nil {
		return nil, fmt.Errorf("cannot update account %s: %s", account.KeyID, err)
	}
	var a objects.Account
	ok, err := s.engine.Where("keyid = ?", account.KeyID).Get(&a)
	if err != nil {
		return nil, fmt.Errorf("couldn't retrieve account %s: %s", account.KeyID, err)
	}
	if ok {
		return &account, nil
	}
	return nil, nil
}

// RevokeAccount revokes an account (on admin/server request)
func (s *Store) RevokeAccount(kid string) error {
	_, err := s.engine.Update(&objects.Account{Status: "revoked"}, &objects.Account{KeyID: kid})
	if err != nil {
		return fmt.Errorf("couldn't retrieve account %s: %s", kid, err)
	}
	return nil
}

// DeactivateAccount deactivas account (on user request)
func (s *Store) DeactivateAccount(kid string) error {
	_, err := s.engine.Update(&objects.Account{Status: "revoked"}, &objects.Account{KeyID: kid})
	if err != nil {
		return fmt.Errorf("couldn't retrieve account %s: %s", kid, err)
	}
	return nil
}
