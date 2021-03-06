package memory

import (
	"fmt"
	"strings"

	"github.com/cblomart/ACMECA/objectstore/objects"
)

// GetAuthorization retrieves an authorization
func (s *Store) GetAuthorization(id string) (*objects.Authorization, error) {
	s.authzmux.Lock()
	defer s.authzmux.Unlock()
	i := -1
	for j, a := range s.authzs {
		if a.ID == id {
			i = j
			break
		}
	}
	if i >= 0 {
		return &s.authzs[i], nil
	}
	return nil, nil
}

// GetAuthorizationByChallenge gets an authorization form a challenge id
func (s *Store) GetAuthorizationByChallenge(id string) (*objects.Authorization, error) {
	s.authzmux.Lock()
	defer s.authzmux.Unlock()
	i := -1
	for j, a := range s.authzs {
		for _, c := range a.Challenges {
			if strings.HasSuffix(c.URL, fmt.Sprintf("/%s", id)) {
				i = j
				break
			}
		}
		if i >= 0 {
			break
		}
	}
	if i >= 0 {
		return &s.authzs[i], nil
	}
	return nil, nil
}

// UpdateAuthorization updates the authrorization
func (s *Store) UpdateAuthorization(authz *objects.Authorization) error {
	// nothing to be done in memory
	return nil
}
