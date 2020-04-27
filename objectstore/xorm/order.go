package xorm

import (
	"fmt"

	"github.com/cblomart/ACMECA/objectstore/objects"
	log "github.com/sirupsen/logrus"
)

// OrdersToIdentifiers links orders to identifiers
type OrdersToIdentifiers struct {
	ID           int64  `xorm:"id pk notnull autoincr"`
	OrderID      string `xorm:"order_id index notnull"`
	IdentifierID int64  `xorm:"identifier_id index notnull"`
}

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
	_, err = s.engine.Insert(order)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot insert order: %s", err)
	}
	// link orders to identities
	for _, id := range order.Identitifers {
		if id.ID == 0 {
			// unknonw identifer id
			var identifier objects.Identifier
			ok, err := s.engine.Where("type = ? and value = ?", id.Type, id.Value).Get(&identifier)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot get identifier %s: %s", id.String(), err)
			}
			if !ok {
				return nil, nil, fmt.Errorf("cannot get identifier %s", id.String())
			}
			id.ID = identifier.ID
		}
		log.Infof("linking order %s to identifier %d", order.ID, id.ID)
		_, err := s.engine.Insert(&OrdersToIdentifiers{OrderID: order.ID, IdentifierID: id.ID})
		if err != nil {
			return nil, nil, fmt.Errorf("cannot link order %s to identifier %d: %s", order.ID, id.ID, err)
		}
	}
	return nil, nil, nil
}

func (s *Store) createAuthorizations(order *objects.Order, authzURL string, challengeURL string) error {
	// find valid authorizations for the account that ordered
	var validAuthz []objects.Authorization
	var authzs []objects.Authorization
	err := s.engine.Where("keyid = ?", order.KeyID).And("status = ?", "valid").Find(&authzs)
	if err != nil {
		return fmt.Errorf("cannot search for valid authz for %s: %s", order.KeyID, err)
	}
	// create authorizations for order
	newauthzs, err := order.CreateAuthz(validAuthz, authzURL, challengeURL)
	if err != nil {
		return fmt.Errorf("cannot create authz for %s: %s", order.KeyID, err)
	}
	// save identifiers and challenges and update them
	for i := range newauthzs {
		// reference the authz
		authz := &newauthzs[i]
		// search if identifier exists
		var id objects.Identifier
		ok, err := s.engine.Where("type = ?", authz.Identifier.Type).And("value = ?", authz.Identifier.Value).Get(&id)
		if err != nil {
			return fmt.Errorf("failed to get identifier %s: %s", authz.Identifier.String(), err)
		}
		if ok {
			log.Infof("updating authz with identifier %s with id %d", id.String(), id.ID)
			authz.Identifier = id
			authz.IdentifierID = id.ID
		} else {
			// create new identifier
			_, err = s.engine.Insert(&authz.Identifier)
			if err != nil {
				return fmt.Errorf("cannot create identifier %s: %s", authz.Identifier.String(), err)
			}
			log.Infof("updating authz with new identifier %s with id %d", authz.Identifier.String(), authz.Identifier.ID)
			authz.IdentifierID = authz.Identifier.ID
		}
		// create challenges
		affected, err := s.engine.Insert(authz.Challenges)
		if err != nil {
			return fmt.Errorf("cannot create challenges for %s: %s", authz.ID, err)
		}
		log.Infof("insert of %d challenges affected %d rows", len(authz.Challenges), affected)
	}
	for _, authz := range newauthzs {
		log.Infof("new authz with identifier %s and id %d", authz.Identifier.String(), authz.Identifier.ID)
	}
	// save authorizations
	_, err = s.engine.Insert(newauthzs)
	if err != nil {
		return fmt.Errorf("cannot insert authz for %s: %s", order.KeyID, err)
	}
	return nil
}

// GetOrder gets an order
func (s *Store) GetOrder(id string, authzPath string) (*objects.Order, error) {
	var order objects.Order
	ok, err := s.engine.ID(id).Get(&order)
	if err != nil {
		return nil, fmt.Errorf("Cannot get order %s: %s", id, err)
	}
	if !ok {
		return nil, fmt.Errorf("Cannot find order %s", id)
	}
	// fill in identifiers
	var links []OrdersToIdentifiers
	err = s.engine.Find(&links, &OrdersToIdentifiers{OrderID: id})
	if err != nil {
		return nil, fmt.Errorf("Cannot get order %s links to identifiers: %s", id, err)
	}
	ids := make([]int64, len(links))
	for i, link := range links {
		ids[i] = link.IdentifierID
	}
	var identifiers []objects.Identifier
	err = s.engine.In("id", ids).Find(&identifiers)
	if err != nil {
		return nil, fmt.Errorf("Cannot get identifiers for order %s: %s", id, err)
	}
	if len(identifiers) == 0 {
		return nil, fmt.Errorf("No identifiers returned for order %s", id)
	}
	order.Identitifers = identifiers
	// fill in authorizations
	var authzs []objects.Authorization
	err = s.engine.Where("keyid = ?", order.KeyID).In("identifierid", ids).Find(&authzs)
	if err != nil {
		return nil, fmt.Errorf("Cannot get authorization for order %s: %s", id, err)
	}
	authzUrls := make([]string, len(authzs))
	for i, authz := range authzs {
		authzUrls[i] = fmt.Sprintf("%s/%s", authzPath, authz.ID)
	}
	order.Authorizations = authzUrls
	return &order, nil
}

// GetOrderByAccount gets orders from an account
func (s *Store) GetOrderByAccount(id string) ([]objects.Order, error) {
	var orders []objects.Order
	err := s.engine.Where("keyid = ?", id).Find(&orders)
	if err != nil {
		return nil, fmt.Errorf("cannot find orders for %s: %s", id, err)
	}
	return orders, nil
}

// UpdateOrder updates an order
func (s *Store) UpdateOrder(order *objects.Order) error {
	_, err := s.engine.Update(order, objects.Order{ID: order.ID})
	if err != nil {
		return fmt.Errorf("could not update order %s: %s", order.ID, err)
	}
	return nil
}

// GetOrderByAuthorization gets an order from an authorization
func (s *Store) GetOrderByAuthorization(id string) ([]objects.Order, error) {
	// get authorization
	var authz objects.Authorization
	ok, err := s.engine.ID(id).Get(&authz)
	if err != nil {
		return nil, fmt.Errorf("could not get authz %s: %s", id, err)
	}
	if !ok {
		return nil, fmt.Errorf("could not find authz %s", id)
	}
	// find authz linked to identity
	var links []OrdersToIdentifiers
	err = s.engine.Find(&links, &OrdersToIdentifiers{IdentifierID: authz.IdentifierID})
	if err != nil {
		return nil, fmt.Errorf("could not get orders to identifers links: %s", err)
	}
	// list concerned order ids
	ids := make([]string, len(links))
	for i, link := range links {
		ids[i] = link.OrderID
	}
	// find orders in the ids for the account
	var orders []objects.Order
	err = s.engine.Where("keyid = ?", authz.KeyID).In("id", ids).Find(&orders)
	if err != nil {
		return nil, fmt.Errorf("couldn't get orders for authz %s: %s", id, err)
	}
	// check that there are some orders
	if len(orders) == 0 {
		return nil, fmt.Errorf("couldn't find orders for authz %s", id)
	}
	return orders, nil
}

// InvalidateOrder invalidates an order
func (s *Store) InvalidateOrder(id string) error {
	_, err := s.engine.Update(&objects.Order{Status: "invalid"}, &objects.Order{ID: id})
	if err != nil {
		return fmt.Errorf("cannot invalidate order %s: %s", id, err)
	}
	return nil
}

// ReadyOrder readies an order
func (s *Store) ReadyOrder(id string) error {
	_, err := s.engine.Update(&objects.Order{Status: "ready"}, &objects.Order{ID: id})
	if err != nil {
		return fmt.Errorf("cannot ready order %s: %s", id, err)
	}
	return nil
}
