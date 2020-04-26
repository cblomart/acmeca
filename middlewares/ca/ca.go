package ca

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// Info adds CA informations to request
func Info(url, password string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("caurl", url)
		c.Set("capass", password)
	}
}

// GetInfo the store from a gin context
func GetInfo(c *gin.Context) (string, string, error) {
	// get the url of the ca
	url, ok := c.Get("caurl")
	if !ok {
		return "", "", fmt.Errorf("ca url not found")
	}
	// get the password of the ca
	pass, ok := c.Get("capass")
	if !ok {
		return "", "", fmt.Errorf("ca password not found")
	}
	return url.(string), pass.(string), nil
}

// GetSigning gets signing informations (cert and key)
func GetSigning(c *gin.Context) (interface{}, error) {
	// get the key
	key, ok := c.Get("cakey")
	if !ok {
		return nil, fmt.Errorf("private key not found")
	}
	return key, nil
}

// Signing adds CA signing capabilities to request
func Signing(cakey interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("cakey", cakey)
	}
}
