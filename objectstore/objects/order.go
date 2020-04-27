package objects

import (
	"fmt"
	"strings"
	"time"

	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/acme/validator"
	"github.com/cblomart/ACMECA/objectstore/utils"

	log "github.com/sirupsen/logrus"
)

// Identifier is the identifier that the client wants to certify
type Identifier struct {
	ID    int64  `json:"-" xorm:"id pk autoincr notnull"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Order reprensets an order from a client
type Order struct {
	ID             string           `json:"-" xorm:"id pk"`
	KeyID          string           `json:"-" xorm:"keyid index"`
	Status         string           `json:"status" xorm:"index"`
	Expires        *time.Time       `json:"expires,omitempty"`
	Identitifers   []Identifier     `json:"identifiers" xorm:"-"`
	NotBefore      *time.Time       `json:"notBefore,omitempty"`
	NotAfter       *time.Time       `json:"notAfter,omitempty"`
	Error          *problem.Problem `json:"error,omitempty" xorm:"-"`
	Authorizations []string         `json:"authorizations" xorm:"-"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate,omitempty"`
}

func (i *Identifier) String() string {
	return fmt.Sprintf("%s:%s", i.Type, i.Value)
}

// CheckOrder check orders
func (o *Order) CheckOrder() (error, error) {
	// identifiers to string array
	strids := make([]string, len(o.Identitifers))
	for i, id := range o.Identitifers {
		strids[i] = id.String()
	}
	// check order
	rejected, unsupported := validator.CheckIdentifiers(&strids)
	if len(unsupported) > 0 {
		log.Errorf("unsupported identifiers in request %s: %s", o.ID, strings.Join(unsupported, ", "))
		return nil, fmt.Errorf("unsupported identifiers in request %s: %s", o.ID, strings.Join(unsupported, ", "))
	}
	if len(rejected) > 0 {
		log.Errorf("rejected identifiers in request %s: %s", o.ID, strings.Join(rejected, ", "))
		return fmt.Errorf("rejected identifiers in request %s: %s", o.ID, strings.Join(rejected, ", ")), nil
	}
	return nil, nil
}

// CreateAuthz creates authorization and challenges for the order
// currauthz is the list of found Authorizations for the account
func (o *Order) CreateAuthz(currauthz []Authorization, authzURL string, challengeURL string) ([]Authorization, error) {
	// copy identities of the order
	ids := make([]Identifier, len(o.Identitifers))
	copy(ids, o.Identitifers)
	// check valid authz for the object
	for _, authz := range currauthz {
		found := -1
		// search for validated identifiers
		for i, id := range ids {
			if authz.Identifier.String() == id.String() &&
				authz.Status == "valid" {
				found = i
				break
			}
		}
		// if found add it to authorizations url and remove the identifier from the list
		if found >= 0 {
			// add to authorizations urls
			o.Authorizations = append(o.Authorizations, fmt.Sprintf("%s/%s", authzURL, authz.ID))
			// remove from list
			ids[found] = ids[len(ids)-1]
			ids = ids[:len(ids)-1]
			continue
		}
	}
	// remainging identifiers needs an authorization
	// create an array for new authorizations created
	newauthzs := make([]Authorization, len(ids))
	// parse identifiers to create authorization
	for i, id := range ids {
		a := Authorization{}
		a.Identifier = id
		a.Expires = time.Now().Add(time.Hour * 24 * AuthorizationValidity)
		a.KeyID = o.KeyID
		a.Status = "pending"
		a.ID = utils.ID()
		// create challenges for each supported challenges
		challengeTypes := strings.Split(AllowedChallengeTypes, ",")
		a.Challenges = make([]Challenge, len(challengeTypes))
		for i, t := range challengeTypes {
			challenge, err := NewChallenge(challengeURL, t, a.ID)
			if err != nil {
				return nil, fmt.Errorf("error creating challenge: %s", err)
			}
			a.Challenges[i] = *challenge
		}
		// add to authorizations urls
		o.Authorizations = append(o.Authorizations, fmt.Sprintf("%s/%s", authzURL, a.ID))
		newauthzs[i] = a
	}
	return newauthzs, nil
}

func (o *Order) String() string {
	identifiers := make([]string, len(o.Identitifers))
	for i, identifier := range o.Identitifers {
		identifiers[i] = identifier.String()
	}
	return fmt.Sprintf("order %s for %s: %s (%s, %s)", o.ID, strings.Join(identifiers, ", "), o.Status, o.Finalize, o.Certificate)
}
