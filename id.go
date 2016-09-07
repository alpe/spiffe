package spiffe

import (
	"fmt"
	"regexp"

	"github.com/gravitational/trace"
)

// TODO(klizhentas) discuss what subset (or full set) we really support
// https://tools.ietf.org/html/rfc2141#section-2.2
// should probably roll proper URN parser before it's too late
var idRegexp = regexp.MustCompile(`urn:spiffe:([a-zA-Z0-9-\._]+)([[a-zA-Z0-9,-\.:_%]*)`)

// ID is a SPIFFE ID
type ID struct {
	// Org is FQDN (fully qualified domain name) of the org, e.g. example.com
	Org string
	// Opaque is opaque part of the ID (name:val) pairs that are up to org
	// to define, e.g. user:alice
	Opaque string
}

func (i *ID) String() string {
	return fmt.Sprintf("urn:spiffe:%v%v", i.Org, i.Opaque)
}

// ParseID parses SPIFEE ID from string
func ParseID(id string) (*ID, error) {
	parts := idRegexp.FindStringSubmatch(id)
	if len(parts) == 0 {
		return nil, trace.BadParameter("SPIFFE ID should look like urn:spiffe:example.com:id:a, got '%v'", id)
	}
	return &ID{
		Org:    parts[1],
		Opaque: parts[2],
	}, nil
}
