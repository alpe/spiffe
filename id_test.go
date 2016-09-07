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

package spiffe

import (
	"testing"

	. "gopkg.in/check.v1"
)

func TestID(t *testing.T) { TestingT(t) }

type IDSuite struct {
}

var _ = Suite(&IDSuite{})

// TestConversion makes sure we convert all trace supported errors
// to and back from GRPC codes
func (s *IDSuite) TestParsing(c *C) {
	type TestCase struct {
		Err      bool
		ID       string
		Expected ID
		Info     string
	}
	testCases := []TestCase{
		// good
		{ID: "urn:spiffe:example.com", Expected: ID{Org: "example.com", Opaque: ""}},
		{ID: "urn:spiffe:example.com:a:b", Expected: ID{Org: "example.com", Opaque: ":a:b"}},
		// bad
		{ID: "", Err: true},
		{ID: "http:spiffe", Err: true},
		{ID: "uri:spiffe", Err: true},
		{ID: "urn:spiffe", Err: true, Info: "missing org part"},
		{ID: "urn:spiffe:", Err: true, Info: "missing org part"},
		{ID: "urn:spiffe:   ", Err: true, Info: "garbage in org part"},
		{ID: "urn:spiffe:   aa", Err: true, Info: "garbage in org part"},
	}
	for i, tc := range testCases {
		comment := Commentf("test case %v #%v id %v", tc.Info, i+1, tc.ID)
		id, err := ParseID(tc.ID)
		if tc.Err {
			c.Assert(err, NotNil, comment)
		} else {
			c.Assert(err, IsNil, comment)
			c.Assert(id, NotNil, comment)
			c.Assert(*id, DeepEquals, tc.Expected, comment)
			c.Assert(id.String(), Equals, tc.ID, comment)
		}
	}
}

// TestExtensions test marshalling/unmarshalling of X509 extensions
func (s *IDSuite) TestExtensions(c *C) {
	id := MustParseID("urn:spiffe:example.com:a:b")
	extension, err := id.X509Extension()
	c.Assert(err, IsNil)
	c.Assert(extension, NotNil)
	out, err := ParseIDsFromX509Extension(*extension)
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 1)
	c.Assert(out[0], DeepEquals, id)
}
