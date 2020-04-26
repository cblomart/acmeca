package decodejws

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/noncestore"
	"github.com/cblomart/ACMECA/middlewares/objectstore"
	"github.com/gin-contrib/location"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

// DecodeJWS is a middleware to decode and validate JWS requests
func DecodeJWS() gin.HandlerFunc {
	return func(c *gin.Context) {
		// only validate nonce on post request
		if c.Request.Method != http.MethodPost {
			return
		}
		os, err := objectstore.Get(c)
		if err != nil {
			log.Errorf("cannot retrieve object store: %s", err)
			problem.ServerInternal(c)
			return
		}
		ns, err := noncestore.Get(c)
		if err != nil {
			log.Errorf("cannot retrieve nonce store: %s", err)
			problem.ServerInternal(c)
			return
		}
		// set nonce in header
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
		// read request body
		rawjws, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			log.Errorf("could not read request body: %s", err)
			problem.ServerInternal(c)
			return
		}
		jws, err := jose.ParseSigned(string(rawjws))
		if err != nil {
			log.Errorf("could decode body: %s", err)
			problem.ServerInternal(c)
			return
		}
		// check that a nonce is present
		if len(jws.Signatures[0].Protected.Nonce) == 0 {
			log.Errorf("nonce not found")
			problem.BadNonce(c)
			return
		}
		if len(jws.Signatures[0].Protected.KeyID) == 0 && jws.Signatures[0].Protected.JSONWebKey == nil {
			// no proper key reference found!
			log.Errorf("neither jwk nor kid indicated in JWS")
			problem.BadPublicKey(c)
			return
		}
		// get the key
		var key interface{}
		if len(jws.Signatures[0].Protected.KeyID) > 0 {
			longkid := jws.Signatures[0].Protected.KeyID
			accountprefix := fmt.Sprintf("%s%s/", url, ep.AccountPath)
			// check id validity
			if !strings.HasPrefix(longkid, accountprefix) {
				log.Errorf("key id not from this ACME: %s", jws.Signatures[0].Protected.KeyID)
				problem.Malformed(c)
				return
			}
			kid := strings.TrimPrefix(longkid, accountprefix)
			// set the key id
			c.Set("kid", kid)
			// retrieve key from key id
			account, err := os.GetAccount(kid)
			if err != nil {
				log.Errorf("error retrieving account with key %s: %s", kid, err)
				problem.ServerInternal(c)
				return
			}
			if account == nil {
				log.Errorf("could not retrieve account with key %s", kid)
				problem.AccountDoesNotExist(c)
				return
			}
			// get the key from account
			rawkey, err := base64.RawURLEncoding.DecodeString(account.Key)
			if err != nil {
				log.Errorf("could not decode key for %s: %s", kid, err)
				problem.ServerInternal(c)
				return
			}
			key, err = x509.ParsePKIXPublicKey(rawkey)
			if err != nil {
				log.Errorf("could not parse pkix key for %s: %s", kid, err)
				problem.ServerInternal(c)
				return
			}
		} else {
			// key provided
			key = jws.Signatures[0].Protected.JSONWebKey.Key
			// encode PKIX
			rawkey, err := x509.MarshalPKIXPublicKey(key)
			if err != nil {
				log.Errorf("could not serialise key: %s", err)
				problem.ServerInternal(c)
				return
			}
			c.Set("key", base64.RawURLEncoding.EncodeToString(rawkey))
		}
		// verify the message
		message, err := jws.Verify(key)
		if err != nil {
			log.Errorf("could not validate jws: %s", err)
			problem.Malformed(c)
			return
		}
		c.Set("payload", message)
		// Validate nonce
		if !ns.ValidateNonce(jws.Signatures[0].Protected.Nonce) {
			log.Errorf("invalid nonce")
			problem.BadNonce(c)
			return
		}
	}
}
