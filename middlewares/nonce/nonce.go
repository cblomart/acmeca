package nonce

import (
	"net/http"

	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/noncestore"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Nonce validates nonce from requests and generate new nonces
func Nonce() gin.HandlerFunc {
	return func(c *gin.Context) {
		// only validate nonce on post request
		if c.Request.Method != http.MethodPost {
			return
		}
		// get the store
		store, err := noncestore.Get(c)
		if err != nil {
			log.Errorf("cannot retrieve store: %s", err)
			problem.ServerInternal(c)
			return
		}
		// debug headers
		for k, v := range c.Request.Header {
			log.Infof("header: %s\tValue: %s", k, v)
		}
		// get the nonce from request
		nonce := c.Request.Header.Get("nonce")
		if nonce == "" {
			log.Errorf("absent nonce in post")
			problem.BadNonce(c)
			return
		}
		// validate the nonce
		if !store.ValidateNonce(nonce) {
			log.Errorf("nonce invalid")
			problem.BadNonce(c)
			return
		}
	}
}
