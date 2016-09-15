/*
Copyright 2016 SPIFFE authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package identity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
)

// TODO(klizhentas) discuss what subset (or full set) we really support
// https://tools.ietf.org/html/rfc2141#section-2.2
// should probably roll proper URN parser before it's too late
var idRegexp = regexp.MustCompile(`urn:spiffe:([a-zA-Z0-9-\._]+)([[a-zA-Z0-9,-\.:_%]*)`)

var oidExtensionSubjectAltName = []int{2, 5, 29, 17}

// tagURN is SubjectAltName registered tag
const tagURN = 6

// ID is a SPIFFE ID
type ID struct {
	// Org is FQDN (fully qualified domain name) of the org, e.g. example.com
	Org string
	// Opaque is opaque part of the ID (name:val) pairs that are up to org
	// to define, e.g. user:alice
	Opaque string
}

func (i *ID) IsEmpty() bool {
	return i.Org == "" && i.Opaque == ""
}

func (i *ID) Check() error {
	_, err := ParseID(i.String())
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (i ID) String() string {
	return fmt.Sprintf("urn:spiffe:%v%v", i.Org, i.Opaque)
}

// x509Extension returns encoded version of x509 certificate URN extension
func (i *ID) X509Extension() (*pkix.Extension, error) {
	// ta
	val, err := asn1.Marshal([]asn1.RawValue{{Tag: 6, Class: 2, Bytes: []byte(i.String())}})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &pkix.Extension{Id: oidExtensionSubjectAltName, Value: val}, nil
}

// IDsFromCertificate returns a list of IDs extracted from X509 extensions
func IDsFromCertificate(cert *x509.Certificate) ([]ID, error) {
	var out []ID
	var err error
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			var ids []ID
			if ids, err = ParseIDsFromX509Extension(e); err != nil {
				return nil, trace.Wrap(err, "failure parsing extesnion %#v", e)
			}
			out = append(out, ids...)
		}
	}
	return out, nil
}

// ParseIDsFromX509Extension finds URN SubjectAltNames that are SPIFFe IDs
// and returns the list of found IDs back
func ParseIDsFromX509Extension(e pkix.Extension) ([]ID, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(e.Value, &seq)
	if err != nil {
		return nil, trace.Wrap(err, "failed unmarshaling asn1.Value")
	}
	if len(rest) != 0 {
		return nil, trace.BadParameter("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return nil, trace.BadParameter("bad SAN sequence %#v", seq)
	}

	var ids []ID
	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, trace.Wrap(err, "")
		}
		if v.Tag == tagURN {
			id, err := ParseID(string(v.Bytes))
			// we choose to ignore malformed, incorrect SPIFFE ids or other types of URNs
			if err != nil {
				log.Warningf("unsupported URN in SubjectAltName: %v", string(v.Bytes))
			} else {
				ids = append(ids, *id)
			}
		}
	}

	return ids, nil
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

// MustParseID panics if it can't parse SPIFFE ID, returns ID otherwise
func MustParseID(val string) ID {
	id, err := ParseID(val)
	if err != nil {
		panic(err)
	}
	return *id
}
