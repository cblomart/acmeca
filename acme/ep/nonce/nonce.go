package nonce

import (
	"fmt"
	"net/http"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/noncestore"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

// Head handles head requests to the nonce endpoint
func Head(c *gin.Context) {
	// get the store to generate nonce
	ns, err := noncestore.Get(c)
	if err != nil {
		log.Errorf("cannot rretrieve store: %s", err)
		problem.ServerInternal(c)
		return
	}
	// generate nonce
	nonce, err := ns.GetNonce()
	if err != nil {
		log.Errorf("error getting nonce: %s", err)
		problem.ServerInternal(c)
		return
	}
	c.Header("Replay-Nonce", nonce)
	url := location.Get(c).String()
	c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
	if c.Request.Method == http.MethodGet {
		c.Status(http.StatusNoContent)
	} else {
		c.Status(http.StatusOK)
	}
}
