package health

import (
	"fmt"
	"net/http"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/middlewares/ca"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Get gets the health state
func Get(c *gin.Context) {
	// get ca informations
	caurl, _, err := ca.GetInfo(c)
	if err != nil {
		log.Errorf("cannot find link to CA: %s", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	cahealthurl := fmt.Sprintf("%s%s", caurl, ep.HealthPath)
	client := http.Client{}
	resp, err := client.Head(cahealthurl)
	if err != nil {
		log.Errorf("cannot check ca health: %s", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Errorf("ca not healthy: %d", resp.StatusCode)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

// CAGet get the health of the CA
func CAGet(c *gin.Context) {
	c.Status(http.StatusOK)
}
