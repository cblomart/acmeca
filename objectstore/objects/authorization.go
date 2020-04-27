package objects

import (
	"fmt"
	"time"

	"github.com/cblomart/ACMECA/acme/validator"
	log "github.com/sirupsen/logrus"
)

const (
	//AuthorizationValidity is the authorization validity in days
	AuthorizationValidity = 92
)

// Authorization represent an authorization and its challenges
type Authorization struct {
	ID           string      `json:"-" xorm:"id pk"`
	KeyID        string      `json:"-" xorm:"keyid index"`
	Identifier   Identifier  `json:"Identifier" xorm:"-"`
	IdentifierID int64       `json:"-" xorm:"identifierid index"`
	Status       string      `json:"status"`
	Expires      time.Time   `json:"expires"`
	Challenges   []Challenge `json:"challenges" xorm:"-"`
}

func (a *Authorization) String() string {
	valid := 0
	invalid := 0
	pending := 0
	for _, c := range a.Challenges {
		switch c.Status {
		case "valid":
			valid++
		case "invalid":
			invalid++
		case "pending":
			pending++
		}
	}
	return fmt.Sprintf("Authorization %s for %s (%d valid, %d invalid, %d pending): %s", a.ID, a.Identifier.String(), valid, invalid, pending, a.Status)
}

//Validate validates a challenge from an authrorization
func (a *Authorization) Validate(id string, key string) *Challenge {
	// get the proper challenge in the authorization
	found := -1
	for i, c := range a.Challenges {
		if c.ID == id {
			found = i
			break
		}
	}
	challenge := &a.Challenges[found]
	if challenge.Status != "pending" {
		return challenge
	}
	challenge.Status = "processing"
	log.Infof("validating challenge %s for identity %s with %s", id, a.Identifier.String(), challenge.Type)
	challenge.Status = validator.Validate(a.Identifier.Value, challenge.Type, challenge.Token, key)
	if a.Status == "pending" {
		a.Status = challenge.Status
		if challenge.Status == "valid" || challenge.Status == "invalid" {
			now := time.Now()
			challenge.Validated = &now
			pending := make([]int, 0)
			for i, c := range a.Challenges {
				if c.Status == "pending" {
					pending = append(pending, i)
				}
			}
			// remove pending challenges
			for i, j := range pending {
				a.Challenges[j] = a.Challenges[len(a.Challenges)-1-i]
			}
			a.Challenges = a.Challenges[:len(a.Challenges)-len(pending)]
		}
	}
	return challenge
}
