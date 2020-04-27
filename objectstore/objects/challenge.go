package objects

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/objectstore/utils"
)

const (
	// AllowedChallengeTypes list the allowed challenge type (comma separated)
	AllowedChallengeTypes = "http-01,tls-alpn-01,dns-01"
	// TokenLength is the length of the token for validation
	TokenLength = 128
)

// Challenge represents a challenge from the provider
type Challenge struct {
	ID            string           `json:"-" xorm:"id pk"`
	Authorization string           `json:"-" xorm:"index"`
	Type          string           `json:"type"`
	URL           string           `json:"url" xorm:"url"`
	Status        string           `json:"status"`
	Validated     *time.Time       `json:"validated,omitempty"`
	Error         *problem.Problem `json:"error,omitempty"`
	Token         string           `json:"token"`
}

// NewChallenge creates a new challenge
func NewChallenge(challengeURL string, challengeType string, authzid string) (*Challenge, error) {
	// check that type is allowed
	allowed := false
	for _, t := range strings.Split(AllowedChallengeTypes, ",") {
		if strings.ToLower(t) == strings.ToLower(challengeType) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("Unallowed challenge type: %s", challengeType)
	}
	// create the challenge
	c := Challenge{
		Type:          challengeType,
		Status:        "pending",
		Authorization: authzid,
	}
	// generate the token
	b := make([]byte, TokenLength)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("Unable to genereate token: %s", err)
	}
	c.Token = base64.RawURLEncoding.EncodeToString(b)
	c.ID = utils.ID()
	c.URL = fmt.Sprintf("%s/%s", challengeURL, c.ID)
	return &c, nil
}
