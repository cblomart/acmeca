package tokenauth

import (
	"encoding/base64"
	"strings"

	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/ca"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// TokenAuth handles authentication function
func TokenAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// check headers for authentication
		auth := c.Request.Header.Get("Authorization")
		if len(auth) == 0 {
			log.Errorf("No Authentication in request")
			problem.Unauthorized(c)
			return
		}
		// check auth
		parts := strings.Split(auth, " ")
		if len(parts) != 2 {
			log.Errorf("Authentication in wrong form")
			problem.Unauthorized(c)
			return
		}
		// check auth type
		if strings.ToLower(parts[0]) != "bearer" {
			log.Errorf("Wrong authentication type: %s", parts[0])
			problem.Unauthorized(c)
			return
		}
		passbytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			log.Errorf("cannot decode password: %s", err)
			problem.Unauthorized(c)
			return
		}
		// get ca inforamtions
		_, capass, err := ca.GetInfo(c)
		if err != nil {
			log.Errorf("cannot find link to CA: %s", err)
			problem.ServerInternal(c)
			return
		}
		// check pass
		if capass != string(passbytes) {
			log.Errorf("cannot decode password: %s", err)
			problem.Unauthorized(c)
			return
		}
	}
}
