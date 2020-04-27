package xorm

import (
	"fmt"

	"github.com/cblomart/ACMECA/objectstore/objects"
	log "github.com/sirupsen/logrus"
)

// GetAuthorization retrieves an authorization
func (s *Store) GetAuthorization(id string) (*objects.Authorization, error) {
	var authz objects.Authorization
	ok, err := s.engine.Where("id = ?", id).Get(&authz)
	if err != nil {
		return nil, fmt.Errorf("couldn't get authz %s: %s", id, err)
	}
	if !ok {
		return nil, nil
	}
	// get the identitier
	var identifier objects.Identifier
	ok, err = s.engine.ID(authz.IdentifierID).Get(&identifier)
	if err != nil {
		return nil, fmt.Errorf("couldn't get identifier %d: %s", authz.IdentifierID, err)
	}
	if !ok {
		return nil, fmt.Errorf("couldn't find identifier %d", authz.IdentifierID)
	}
	authz.Identifier = identifier
	// fill in challenges for the authz
	var challenges []objects.Challenge
	err = s.engine.Find(&challenges, &objects.Challenge{Authorization: authz.ID})
	if err != nil {
		return nil, fmt.Errorf("couldn't get challenges for auth %s: %s", id, err)
	}
	log.Infof("found %d challenges for authz %s", len(challenges), authz.ID)
	authz.Challenges = challenges
	return &authz, nil
}

// GetAuthorizationByChallenge gets an authorization form a challenge id
func (s *Store) GetAuthorizationByChallenge(id string) (*objects.Authorization, error) {
	var challenge objects.Challenge
	ok, err := s.engine.ID(id).Get(&challenge)
	if err != nil {
		return nil, fmt.Errorf("couldn't get challenge %s: %s", id, err)
	}
	if !ok {
		return nil, fmt.Errorf("couldn't get challenge %s", id)
	}
	var authz objects.Authorization
	ok, err = s.engine.ID(challenge.Authorization).Get(&authz)
	if err != nil {
		return nil, fmt.Errorf("couldn't get auth %s for challenge %s: %s", challenge.Authorization, id, err)
	}
	if !ok {
		return nil, fmt.Errorf("couldn't find auth %s for challenge %s", challenge.Authorization, id)
	}
	// get identitier
	var identifier objects.Identifier
	ok, err = s.engine.ID(authz.IdentifierID).Get(&identifier)
	if err != nil {
		return nil, fmt.Errorf("couldn't get identifier %d for auth %s: %s", authz.IdentifierID, authz.ID, err)
	}
	if !ok {
		return nil, fmt.Errorf("couldn't find identifier %d for auth %s", authz.IdentifierID, authz.ID)
	}
	authz.Identifier = identifier
	// get challenges
	var challenges []objects.Challenge
	err = s.engine.Find(&challenges, &objects.Challenge{Authorization: authz.ID})
	if err != nil {
		return nil, fmt.Errorf("couldn't get challenges for auth %s: %s", authz.ID, err)
	}
	authz.Challenges = challenges
	return &authz, nil
}

// UpdateAuthorization updates the authrorization
func (s *Store) UpdateAuthorization(authz *objects.Authorization) error {
	// update challenges
	var challengeIds []string
	for _, challenge := range authz.Challenges {
		challengeIds = append(challengeIds, challenge.ID)
		_, err := s.engine.Update(challenge, &objects.Challenge{ID: challenge.ID})
		if err != nil {
			return fmt.Errorf("cannot update challenge %s of authz %s: %s", challenge.ID, authz.ID, err)
		}
	}
	// update authz
	_, err := s.engine.Update(authz, objects.Authorization{ID: authz.ID})
	if err != nil {
		return fmt.Errorf("cannot update authorization %s: %s", authz.ID, err)
	}
	// propagate challenge removal
	var challenges []objects.Challenge
	err = s.engine.Find(&challenges, &objects.Challenge{Authorization: authz.ID})
	if err != nil {
		return fmt.Errorf("cannot get challenges from authz %s: %s", authz.ID, err)
	}
	for _, c := range challenges {
		found := false
		for _, i := range challengeIds {
			if i == c.ID {
				found = true
				break
			}
		}
		if found {
			continue
		}
		// delete challenge
		_, err := s.engine.Delete(&objects.Challenge{ID: c.ID, Authorization: authz.ID})
		if err != nil {
			return fmt.Errorf("cannot remove challenge %s from authz %s: %s", c.ID, authz.ID, err)
		}
	}
	return nil
}
