package challenge

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/objectstore"
	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/location"

	log "github.com/sirupsen/logrus"
)

// Post handles a post request to order enpoint
func Post(c *gin.Context) {
	// get the use key id
	var kid string
	if tmp, ok := c.Get("kid"); ok {
		kid = fmt.Sprintf("%s", tmp)
	}
	// call to order must be identified
	if len(kid) == 0 {
		log.Errorf("recieved an order from an unidentified user")
		problem.Unauthorized(c)
		return
	}
	// check the id of the request
	id := strings.Trim(c.Param("id"), "/")
	if len(id) == 0 {
		log.Errorf("no specific challenge requested")
		problem.Malformed(c)
		return
	}
	store, err := objectstore.Get(c)
	if err != nil {
		log.Errorf("cannot rretrieve store: %s", err)
		problem.ServerInternal(c)
		return
	}
	authz, err := store.GetAuthorizationByChallenge(id)
	if err != nil {
		log.Errorf("cannot retrieve auhthz: %s", err)
		problem.ServerInternal(c)
		return
	}
	if authz == nil {
		log.Infof("no authz found with challenge id %s", id)
		c.Status(http.StatusNotFound)
		return
	}
	// check authorization
	if authz.KeyID != kid {
		log.Errorf("query from authorization from wrong user")
		problem.Unauthorized(c)
		return
	}
	account, err := store.GetAccount(kid)
	if err != nil || account == nil {
		log.Errorf("cannot retrieve account %s: %s", kid, err)
		problem.AccountDoesNotExist(c)
		return
	}
	// validating authorization's challenge
	challenge := authz.Validate(id, account.Key)
	if challenge == nil {
		log.Infof("no challenge found with id %s", id)
		c.Status(http.StatusNotFound)
		return
	}
	// save authz
	err = store.UpdateAuthorization(authz)
	if err != nil {
		log.Infof("could not update authorization")
		problem.ServerInternal(c)
		return
	}
	if authz.Status == "valid" {
		// check orders
		orders, err := store.GetOrderByAuthorization(authz.ID)
		if err != nil {
			log.Infof("could not retrieve orders from authorization")
			problem.ServerInternal(c)
			return
		}
		// check orders
		for _, order := range orders {
			// only check pending orders
			if order.Status != "pending" {
				log.Warnf("Authorization updated for order not pending!")
				continue
			}
			// check atuhtorization status for orders
			valid := 0
			invalid := 0 // includes revoked, expired, deactivated
			pending := 0
			url := location.Get(c).String()
			basePath := fmt.Sprintf("%s%s/", url, ep.AuthzPath)
			for _, orderAuthURL := range order.Authorizations {
				if !strings.HasPrefix(orderAuthURL, basePath) {
					log.Errorf("Authorization not pointing to this server auth basepath")
					problem.ServerInternal(c)
					return
				}
				id := strings.TrimPrefix(orderAuthURL, basePath)
				orderAuthz, err := store.GetAuthorization(id)
				if err != nil || orderAuthz == nil {
					log.Errorf("Authorization with id %s not found", id)
					problem.ServerInternal(c)
					return
				}
				switch orderAuthz.Status {
				case "valid":
					valid++
				case "pending":
					pending++
				default:
					invalid++
				}
			}
			if invalid > 0 {
				store.InvalidateOrder(order.ID)
			} else if valid == len(order.Authorizations) {
				store.ReadyOrder(order.ID)
			}
			if order.Status == "pending" {
				continue
			}
			if err != nil {
				log.Errorf("Could not update order %s", order.ID)
				problem.ServerInternal(c)
				return
			}
		}
	}
	c.JSON(http.StatusOK, challenge)
}
