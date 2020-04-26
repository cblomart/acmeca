package nocache

import "github.com/gin-gonic/gin"

// NoCache add the cache-control headers
func NoCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
	}
}
