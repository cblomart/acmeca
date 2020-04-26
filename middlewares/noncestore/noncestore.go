package noncestore

import (
	"fmt"

	acmestore "github.com/cblomart/ACMECA/noncestore"
	"github.com/gin-gonic/gin"
)

// Store adds ACME storage to the request
func Store(store acmestore.NonceStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("noncestore", store)
	}
}

// Get the store from a gin context
func Get(c *gin.Context) (acmestore.NonceStore, error) {
	// get the store to resolve accounts
	s, ok := c.Get("noncestore")
	if !ok {
		return nil, fmt.Errorf("storage not found")
	}
	return s.(acmestore.NonceStore), nil
}
