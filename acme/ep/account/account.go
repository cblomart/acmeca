package account

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/objectstore"
	"github.com/cblomart/ACMECA/objectstore/objects"
	"github.com/cblomart/ACMECA/objectstore/utils"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

// Req is the request of an account
type Req struct {
	objects.Account
	OnlyReturnExisting bool `json:"onlyReturnExisting"`
}

// ToAccount converts request back to account
func (r *Req) ToAccount() objects.Account {
	return objects.Account{
		KeyID:                r.KeyID,
		Key:                  r.Key,
		Contact:              r.Contact,
		Status:               r.Status,
		TermsOfServiceAgreed: r.TermsOfServiceAgreed,
	}
}

//Post handles post requests to the account endpoint
func Post(c *gin.Context) {
	// get information from jws
	var payload string
	if tmp, ok := c.Get("payload"); ok {
		payload = fmt.Sprintf("%s", tmp)
	}
	var kid string
	if tmp, ok := c.Get("kid"); ok {
		kid = fmt.Sprintf("%s", tmp)
	}
	var key string
	if tmp, ok := c.Get("key"); ok {
		key = fmt.Sprintf("%s", tmp)
	}
	reqKid := strings.Trim(c.Param("id"), "/")
	// kid should be the same as requested key (kid wins)
	if len(kid) > 0 && kid != reqKid {
		log.Error("kid provided mismatch requested kid")
		problem.Malformed(c)
		return
	}
	// kid (or reqKid) and key shoudn't be provided together
	if len(kid) > 0 && len(key) > 0 {
		log.Error("jwk and kid shouldn't be provided together")
		problem.Malformed(c)
		return
	}
	// get the store to resolve accounts
	store, err := objectstore.Get(c)
	if err != nil {
		log.Errorf("cannot retrieve store: %s", err)
		problem.ServerInternal(c)
		return
	}
	// try to decode account if exists
	reqAccount := &Req{}
	if len(payload) > 0 {
		err := json.Unmarshal([]byte(payload), reqAccount)
		if err != nil {
			log.Errorf("cannot unmarshal requested account: %s", err)
			problem.ServerInternal(c)
			return
		}
	}
	url := location.Get(c).String()
	if len(kid) > 0 {
		// get or update
		// look for account with kid
		existing, err := store.GetAccount(kid)
		if err != nil {
			log.Errorf("cannot recover account with %s: %s", kid, err)
			problem.ServerInternal(c)
			return
		}
		c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
		if existing == nil {
			c.Status(http.StatusNotFound)
			return
		}
		if reqAccount == nil {
			// if accound found return it
			c.JSON(http.StatusOK, existing)
			return
		}
		if reqAccount.OnlyReturnExisting {
			c.JSON(http.StatusOK, existing)
			return
		}
		reqAccount.KeyID = existing.KeyID
		reqAccount.Key = existing.Key
		updated, err := store.UpdateAccount(reqAccount.ToAccount())
		if err != nil {
			log.Errorf("cannot update account %s: %s", reqAccount.KeyID, err)
			problem.ServerInternal(c)
			return
		}
		c.JSON(http.StatusOK, updated)
		return
	}
	if len(key) > 0 {
		// look for account with key
		existing, err := store.GetAccountFromKey(key)
		if err != nil {
			log.Errorf("cannot recover account: %s", err)
			problem.ServerInternal(c)
			return
		}
		c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
		if existing != nil {
			// if accound found return it
			c.JSON(http.StatusOK, existing)
			return
		}
		if reqAccount != nil {
			if reqAccount.OnlyReturnExisting {
				log.Infof("no account with provided key found: %s", key)
				c.Status(http.StatusNotFound)
				return
			}
			// no account found so creating
			reqAccount.KeyID = utils.ID()
			//set headers
			c.Header("Location", fmt.Sprintf("%s%s/%s", url, ep.AccountPath, reqAccount.KeyID))
			reqAccount.Key = key
			reqAccount.Status = "valid"
			reqAccount.Orders = fmt.Sprintf("%s%s/%s", url, ep.OrderPath, reqAccount.KeyID)
			err := store.CreateAccount(reqAccount.ToAccount())
			if err != nil {
				log.Errorf("cannot recover account: %s", err)
				problem.ServerInternal(c)
				return
			}
			jsonaccount, _ := json.Marshal(reqAccount)
			log.Infof("created account: %s", jsonaccount)
			c.JSON(http.StatusCreated, reqAccount)
			return
		}
	}
	log.Warnf("hitting a sore spot")
	log.Warnf("kid: %s", kid)
	log.Warnf("key: %s", key)
	log.Warnf("payload: %s", payload)
	c.Status(http.StatusNotImplemented)
}
