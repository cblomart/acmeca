package objectstore

import (
	"fmt"

	"github.com/cblomart/ACMECA/objectstore/memory"
	"github.com/cblomart/ACMECA/objectstore/objects"

	log "github.com/sirupsen/logrus"
)

const (
	// MemoryStore stores ACME objects in memory
	MemoryStore = "memory"
)

// ObjectStore is the interface for storage
type ObjectStore interface {
	// Generic information
	Type() string

	// Account management

	// GetAccount gets an existing account from key id
	GetAccount(kid string) (*objects.Account, error)
	// GetAccount gets an existing account from key
	GetAccountFromKey(key string) (*objects.Account, error)
	// CreateAccount creates an account
	CreateAccount(account objects.Account) error
	// UpdateAccount updates an account
	UpdateAccount(account objects.Account) (*objects.Account, error)
	// RevokeAccount revokes an account (on admin/server request)
	RevokeAccount(kid string) error
	// DeactivateAccount deactivas account (on user request)
	DeactivateAccount(kid string) error

	// Order manangement

	// CreateOrder creates an order
	CreateOrder(order *objects.Order, authzURL string, challengeURL string, finalizeURL string) (rejected error, unsupported error, other error)
	// GetOrder gets an order
	GetOrder(id string) (*objects.Order, error)
	// GetOrderByAccount gets orders from an account
	GetOrderByAccount(id string) ([]*objects.Order, error)
	// GetOrderByAuthorization gets an order from an authorization
	GetOrderByAuthorization(id string) ([]*objects.Order, error)
	// InvalidateOrder invalidates an order
	InvalidateOrder(id string) error
	// ReadyOrder makes an order ready
	ReadyOrder(id string) error
	// UpdateOrder updates an order
	UpdateOrder(order *objects.Order) error

	// Authorization management

	// GetAuthorization gets an authorization
	GetAuthorization(id string) (*objects.Authorization, error)
	// GetAuthorizationByChallenge gets an authorization form a challenge id
	GetAuthorizationByChallenge(id string) (*objects.Authorization, error)
	// UpdateAuthorization updates an authorization
	UpdateAuthorization(authz *objects.Authorization) error
}

// Factory creates a store in function of its type
func Factory(storeType string, args map[string]string) (ObjectStore, error) {
	switch storeType {
	case MemoryStore:
		return &memory.Store{}, nil
	default:
		log.Errorf("unknown object store type requested: %s", storeType)
		return nil, fmt.Errorf("unknown object store type requested: %s", storeType)
	}
}
