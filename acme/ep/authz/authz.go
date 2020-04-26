package authz

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/objectstore"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"

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
	url := location.Get(c).String()
	store, err := objectstore.Get(c)
	if err != nil {
		log.Errorf("cannot rretrieve store: %s", err)
		problem.ServerInternal(c)
		return
	}
	// check the id of the request
	id := strings.Trim(c.Param("id"), "/")
	if len(id) == 0 {
		log.Errorf("no specific authorization requested")
		problem.Malformed(c)
		return
	}
	authz, err := store.GetAuthorization(id)
	if err != nil {
		log.Errorf("cannot retrieve auhthz: %s", err)
		problem.ServerInternal(c)
		return
	}
	if authz == nil {
		log.Infof("no authz found with id %s", id)
		c.Status(http.StatusNotFound)
		return
	}
	// check authorization
	if authz.KeyID != kid {
		log.Errorf("query from authorization from wrong user")
		problem.Unauthorized(c)
		return
	}
	c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
	log.Info(authz.String())
	c.JSON(http.StatusOK, authz)
	return
}
