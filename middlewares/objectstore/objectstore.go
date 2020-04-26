package objectstore

import (
	"fmt"

	acmestore "github.com/cblomart/ACMECA/objectstore"
	"github.com/gin-gonic/gin"
)

// Store adds ACME storage to the request
func Store(store acmestore.ObjectStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("objectstore", store)
	}
}

// Get the store from a gin context
func Get(c *gin.Context) (acmestore.ObjectStore, error) {
	// get the store to resolve accounts
	s, ok := c.Get("objectstore")
	if !ok {
		return nil, fmt.Errorf("storage not found")
	}
	return s.(acmestore.ObjectStore), nil
}
