package directory

import (
	"net/http"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
)

// Directory represents the ACME directory
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// Get handles get request to directory
func Get(c *gin.Context) {
	url := location.Get(c).String()
	dir := Directory{
		NewNonce:   url + ep.NoncePath,
		NewAccount: url + ep.AccountPath,
		NewOrder:   url + ep.OrderPath,
		RevokeCert: url + ep.RevokePath,
		KeyChange:  url + ep.KeyPath,
	}
	c.JSON(http.StatusOK, dir)
}
