package problem

import (
	"fmt"
	"net/http"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
)

const (
	typeAccountDoesNotExist     = "urn:ietf:params:acme:error:accountDoesNotExist"
	typeAlreadyRevoked          = "urn:ietf:params:acme:error:alreadyRevoked"
	typeBadCSR                  = "urn:ietf:params:acme:error:badCSR"
	typeBadNonce                = "urn:ietf:params:acme:error:badNonce"
	typeBadPublicKey            = "urn:ietf:params:acme:error:badPublicKey"
	typeBadSignatureAlgorithm   = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	typeBadRevocationReason     = "urn:ietf:params:acme:error:badRevocationReason"
	typeCaa                     = "urn:ietf:params:acme:error:caa"
	typeCompound                = "urn:ietf:params:acme:error:compound"
	typeConnection              = "urn:ietf:params:acme:error:connection"
	typeDNS                     = "urn:ietf:params:acme:error:dns"
	typeExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired"
	typeIncorrectResponse       = "urn:ietf:params:acme:error:incorrectResponse"
	typeInvalidContact          = "urn:ietf:params:acme:error:invalidContact"
	typeMalformed               = "urn:ietf:params:acme:error:malformed"
	typeOrderNotReady           = "urn:ietf:params:acme:error:orderNotReady"
	typeRateLimited             = "urn:ietf:params:acme:error:rateLimited"
	typeRejectedIdentifier      = "urn:ietf:params:acme:error:rejectedIdentifier"
	typeServerInternal          = "urn:ietf:params:acme:error:serverInternal"
	typeTLS                     = "urn:ietf:params:acme:error:tls"
	typeUnauthorized            = "urn:ietf:params:acme:error:unauthorized"
	typeUnsupportedContact      = "urn:ietf:params:acme:error:unsupportedContact"
	typeUnsupportedIdentifier   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	typeUserActionRequired      = "urn:ietf:params:acme:error:userActionRequired"
	descAccountDoesNotExist     = "The request specified an account that does not exist"
	descAlreadyRevoked          = "The request specified a certificate to be revoked that has already been revoked"
	descBadCSR                  = "The CSR is unacceptable (e.g., due to a short key)"
	descBadNonce                = "The client sent an unacceptable anti-replay nonce"
	descBadPublicKey            = "The JWS was signed by a public key the server does not support"
	descBadRevocationReason     = "The revocation reason provided is not allowed by the server"
	descBadSignatureAlgorithm   = "The JWS was signed with an algorithm the server does not support"
	descCaa                     = "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate"
	descCompound                = "Specific error conditions are indicated in the “subproblems” array."
	descConnection              = "The server could not connect to validation target"
	descDNS                     = "There was a problem with a DNS query during identifier validation"
	descExternalAccountRequired = "The request must include a value for the “externalAccountBinding” field"
	descIncorrectResponse       = "Response received didn’t match the challenge’s requirements"
	descInvalidContact          = "A contact URL for an account was invalid"
	descMalformed               = "The request message was malformed"
	descOrderNotReady           = "The request attempted to finalize an order that is not ready to be finalized"
	descRateLimited             = "The request exceeds a rate limit"
	descRejectedIdentifier      = "The server will not issue certificates for the identifier"
	descServerInternal          = "The server experienced an internal error"
	descTLS                     = "The server received a TLS error during validation"
	descUnauthorized            = "The client lacks sufficient authorization"
	descUnsupportedContact      = "A contact URL for an account used an unsupported protocol scheme"
	descUnsupportedIdentifier   = "An identifier is of an unsupported type"
	descUserActionRequired      = "Visit the “instance” URL and take actions specified there"
)

// Problem describes an issue
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func problem(c *gin.Context, problemType string, problemDetail string, status int) {
	p := Problem{
		Type:   problemType,
		Detail: problemDetail,
		Status: status,
	}
	url := location.Get(c).String()
	c.Header("Content-Type", "application/problem+json")
	c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
	c.JSON(status, p)
	c.Abort()
}

// AccountDoesNotExist ACME problem accountDoesNotExist
func AccountDoesNotExist(c *gin.Context) {
	problem(c, typeAccountDoesNotExist, descAccountDoesNotExist, http.StatusNotFound)
}

// AlreadyRevoked ACME problem alreadyRevoked
func AlreadyRevoked(c *gin.Context) {
	problem(c, typeAlreadyRevoked, descAlreadyRevoked, http.StatusLocked)
}

// BadCSR ACME problem badCSR
func BadCSR(c *gin.Context) {
	problem(c, typeBadCSR, descBadCSR, http.StatusBadRequest)
}

// BadNonce ACME problem badNonce
func BadNonce(c *gin.Context) {
	problem(c, typeBadNonce, descBadNonce, http.StatusBadRequest)
}

// BadPublicKey ACME problem badPublicKey
func BadPublicKey(c *gin.Context) {
	problem(c, typeBadPublicKey, descBadPublicKey, http.StatusBadRequest)
}

// BadRevocationReason ACME problem badRevocationReason
func BadRevocationReason(c *gin.Context) {
	problem(c, typeBadRevocationReason, descBadRevocationReason, http.StatusBadRequest)
}

// BadSignatureAlgorithm ACME problem badSignatureAlgorithm
func BadSignatureAlgorithm(c *gin.Context) {
	problem(c, typeBadSignatureAlgorithm, descBadSignatureAlgorithm, http.StatusBadRequest)
}

// Caa ACME problem caa
func Caa(c *gin.Context) {
	problem(c, typeCaa, descCaa, http.StatusForbidden)
}

// Compound ACME problem compound
func Compound(c *gin.Context) {
	problem(c, typeCompound, descCompound, http.StatusBadRequest)
}

// Connection ACME problem connection
func Connection(c *gin.Context) {
	problem(c, typeConnection, descConnection, http.StatusNotFound)
}

// DNS ACME problem dns
func DNS(c *gin.Context) {
	problem(c, typeDNS, descDNS, http.StatusNotFound)
}

// ExternalAccountRequired ACME problem externalAccountRequired
func ExternalAccountRequired(c *gin.Context) {
	problem(c, typeExternalAccountRequired, descExternalAccountRequired, http.StatusFailedDependency)
}

// IncorrectResponse ACME problem incorrectResponse
func IncorrectResponse(c *gin.Context) {
	problem(c, typeIncorrectResponse, descIncorrectResponse, http.StatusExpectationFailed)
}

// InvalidContact ACME problem invalidContact
func InvalidContact(c *gin.Context) {
	problem(c, typeInvalidContact, descInvalidContact, http.StatusBadRequest)
}

// Malformed ACME problem malformed
func Malformed(c *gin.Context) {
	problem(c, typeMalformed, descMalformed, http.StatusBadRequest)
}

// OrderNotReady ACME problem orderNotReady
func OrderNotReady(c *gin.Context) {
	problem(c, typeOrderNotReady, descOrderNotReady, http.StatusTooEarly)
}

// RateLimited ACME problem rateLimited
func RateLimited(c *gin.Context) {
	problem(c, typeRateLimited, descRateLimited, http.StatusTooManyRequests)
}

// RejectedIdentifier ACME problem rejectedIdentifier
func RejectedIdentifier(c *gin.Context) {
	problem(c, typeRejectedIdentifier, descRejectedIdentifier, http.StatusUnauthorized)
}

// ServerInternal ACME problem serverInternal
func ServerInternal(c *gin.Context) {
	problem(c, typeServerInternal, descServerInternal, http.StatusInternalServerError)
}

// TLS ACME problem tls
func TLS(c *gin.Context) {
	problem(c, typeTLS, descTLS, http.StatusFailedDependency)
}

// Unauthorized ACME problem unauthorized
func Unauthorized(c *gin.Context) {
	problem(c, typeUnauthorized, descUnauthorized, http.StatusUnauthorized)
}

// UnsupportedContact ACME problem unsupportedContact
func UnsupportedContact(c *gin.Context) {
	problem(c, typeUnsupportedContact, descUnsupportedContact, http.StatusBadRequest)
}

// UnsupportedIdentifier ACME problem unsupportedIdentifier
func UnsupportedIdentifier(c *gin.Context) {
	problem(c, typeUnsupportedIdentifier, descUnsupportedIdentifier, http.StatusBadRequest)
}

// UserActionRequired ACME problem userActionRequired
func UserActionRequired(c *gin.Context) {
	problem(c, typeUserActionRequired, descUserActionRequired, http.StatusFailedDependency)
}
