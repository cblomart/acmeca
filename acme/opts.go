package acme

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

// GetOpts decodes an array of key value to a map
// options separator is ",", keyvalue separator is ":"
func GetOpts(stringopts string) map[string]string {
	opts := map[string]string{}
	kvGroups := strings.Split(stringopts, ";")
	for _, opt := range kvGroups {
		kv := strings.Split(opt, "=")
		if len(kv) != 2 {
			log.Warnf("unrecognized option: %s", opt)
			continue
		}
		opts[kv[0]] = kv[1]
	}
	return opts
}
