package validator

import (
	"strings"
)

const (
	// SupportedTypes list supporte identifier types
	SupportedTypes = "dns"
)

var (
	//AllowedDomains  Allowed Domains to deliver certificates to
	AllowedDomains = ""
)

// CheckIdentifier checks if an identifier is supported
// to avoid cyclic import validator should not depend on objects
func CheckIdentifier(id string) (rejected bool, unsupported bool) {
	// separate type and value
	parts := strings.Split(id, ":")
	if len(parts) != 2 {
		return true, false
	}
	idType := parts[0]
	idValue := parts[1]
	// check type
	typeOk := false
	for _, t := range strings.Split(SupportedTypes, ",") {
		if idType == t {
			typeOk = true
			break
		}
	}
	valueOk := false
	for _, d := range strings.Split(strings.ToLower(AllowedDomains), ",") {
		if strings.HasSuffix(strings.ToLower(idValue), d) {
			valueOk = true
			break
		}
	}
	// all check passed
	return !valueOk, !typeOk
}

// CheckIdentifiers check multiple identifiers
func CheckIdentifiers(ids *[]string) (rejected []string, unsupported []string) {
	rejected = make([]string, 0)
	unsupported = make([]string, 0)
	for _, id := range *ids {
		idrejected, idunsupported := CheckIdentifier(id)
		if idrejected {
			rejected = append(rejected, id)
		}
		if idunsupported {
			unsupported = append(unsupported, id)
		}
	}
	return rejected, unsupported
}
