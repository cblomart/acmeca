package certstore

import (
	"fmt"

	acmestore "github.com/cblomart/ACMECA/certstore"
	"github.com/gin-gonic/gin"
)

// Store adds ACME storage to the request
func Store(store acmestore.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("certstore", store)
	}
}

// Get the store from a gin context
func Get(c *gin.Context) (acmestore.CertStore, error) {
	// get the store to resolve accounts
	s, ok := c.Get("certstore")
	if !ok {
		return nil, fmt.Errorf("storage not found")
	}
	return s.(acmestore.CertStore), nil
}
