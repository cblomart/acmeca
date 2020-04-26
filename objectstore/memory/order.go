package memory

import (
	"fmt"
	"strings"

	"github.com/cblomart/ACMECA/objectstore/objects"
)

// CreateOrder creates an order
func (s *Store) CreateOrder(order *objects.Order, authzURL string, challengeURL string, finalizeURL string) (error, error, error) {
	rejected, unsupported := order.CheckOrder()
	if rejected != nil || unsupported != nil {
		return rejected, unsupported, nil
	}
	order.Status = "pending"
	order.Finalize = fmt.Sprintf("%s/%s", finalizeURL, order.ID)
	err := s.createAuthorizations(order, authzURL, challengeURL)
	if err != nil {
		return nil, nil, err
	}
	s.ordmux.Lock()
	defer s.ordmux.Unlock()
	s.orders = append(s.orders, *order)
	return nil, nil, nil
}

func (s *Store) createAuthorizations(order *objects.Order, authzURL string, challengeURL string) error {
	// find valid authorizations for the account that ordered
	validAuthz := make([]objects.Authorization, 0)
	s.authzmux.Lock()
	defer s.authzmux.Unlock()
	for _, a := range s.authzs {
		if a.KeyID == order.KeyID && a.Status == "valid" {
			validAuthz = append(validAuthz, a)
		}
	}
	// create authorizations for order
	authz, err := order.CreateAuthz(validAuthz, authzURL, challengeURL)
	if err != nil {
		return err
	}
	// save authorizations
	s.authzs = append(s.authzs, *authz...)
	return nil
}

func (s *Store) getOrder(id string) int {
	s.ordmux.Lock()
	defer s.ordmux.Unlock()
	i := -1
	for j, o := range s.orders {
		if o.ID == id {
			i = j
			break
		}
	}
	return i
}

// GetOrder gets an order
func (s *Store) GetOrder(id string) (*objects.Order, error) {
	i := s.getOrder(id)
	if i >= 0 {
		return &s.orders[i], nil
	}
	return nil, nil
}

// GetOrderByAccount gets orders from an account
func (s *Store) GetOrderByAccount(id string) ([]*objects.Order, error) {
	orders := make([]*objects.Order, 0)
	s.ordmux.Lock()
	defer s.ordmux.Unlock()
	for _, o := range s.orders {
		if o.KeyID == id {
			orders = append(orders, &o)
		}
	}
	return orders, nil
}

// UpdateOrder updates an order
func (s *Store) UpdateOrder(order *objects.Order) error {
	// nothing to be made in memory
	return nil
}

// GetOrderByAuthorization gets an order from an authorization
func (s *Store) GetOrderByAuthorization(id string) ([]*objects.Order, error) {
	// create list of orders
	orders := make([]*objects.Order, 0)
	// parse each order
	s.ordmux.Lock()
	defer s.ordmux.Unlock()
	for _, o := range s.orders {
		// parse authorizations in order
		for _, a := range o.Authorizations {
			if strings.HasSuffix(a, fmt.Sprintf("/%s", id)) {
				orders = append(orders, &o)
			}
		}
	}
	return orders, nil
}

// InvalidateOrder invalidates an order
func (s *Store) InvalidateOrder(id string) error {
	i := s.getOrder(id)
	s.ordmux.Lock()
	defer s.ordmux.Unlock()
	s.orders[i].Status = "invalid"
	return nil
}

// ReadyOrder readies an order
func (s *Store) ReadyOrder(id string) error {
	i := s.getOrder(id)
	s.ordmux.Lock()
	defer s.ordmux.Unlock()
	s.orders[i].Status = "ready"
	return nil
}
