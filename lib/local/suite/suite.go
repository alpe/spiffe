/*
Copyright 2016 SPIFFE Authors

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

// package suite contains local services acceptance test suite
package suite

import (
	"path/filepath"
	"time"

	"github.com/spiffe/spiffe/lib/local"
	"github.com/spiffe/spiffe/lib/workload"
	wsuite "github.com/spiffe/spiffe/lib/workload/suite"

	"golang.org/x/net/context"
	. "gopkg.in/check.v1"
)

type LocalSuite struct {
	R local.Renewer
	S workload.Service
}

func (s *LocalSuite) CertRequestsCRUD(c *C) {
	ctx := context.TODO()
	ca := workload.CertAuthority{
		ID:         "example.com",
		Cert:       []byte(wsuite.CertAuthorityCertPEM),
		PrivateKey: []byte(wsuite.CertAuthorityKeyPEM),
	}
	err := s.S.UpsertCertAuthority(ctx, ca)
	c.Assert(err, IsNil)

	targetDir := c.MkDir()

	req := local.CertRequest{
		ID:              targetDir,
		CertAuthorityID: ca.ID,
		Identity:        wsuite.BobID,
		CommonName:      "example.com",
		TTL:             time.Minute,
		CertPath:        filepath.Join(targetDir, "cert.pem"),
		KeyPath:         filepath.Join(targetDir, "key.pem"),
		CAPath:          filepath.Join(targetDir, "ca.pem"),
	}
	err = s.R.CreateCertRequest(ctx, req)
	c.Assert(err, IsNil)

	out, err := s.R.GetCertRequests(ctx)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, []local.CertRequest{req})

	err = s.R.DeleteCertRequest(ctx, req.ID)
	c.Assert(err, IsNil)

	out, err = s.R.GetCertRequests(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 0)
}

func (s *LocalSuite) BundleRequestsCRUD(c *C) {
	ctx := context.TODO()

	bundle := workload.TrustedRootBundle{
		ID: "prod",
		Certs: []workload.TrustedRootCert{{
			ID:   "example.com",
			Cert: []byte(wsuite.CertAuthorityCertPEM),
		}},
	}
	err := s.S.CreateTrustedRootBundle(ctx, bundle)
	c.Assert(err, IsNil)

	targetDir := c.MkDir()

	req := local.BundleRequest{
		ID:        targetDir,
		BundleID:  bundle.ID,
		TargetDir: targetDir,
	}
	err = s.R.CreateBundleRequest(ctx, req)
	c.Assert(err, IsNil)

	out, err := s.R.GetBundleRequests(ctx)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, []local.BundleRequest{req})

	err = s.R.DeleteBundleRequest(ctx, req.ID)
	c.Assert(err, IsNil)

	out, err = s.R.GetBundleRequests(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 0)
}
