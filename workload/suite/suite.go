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

// package suite contains a workload services acceptance test suite
package suite

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	"github.com/spiffe/spiffe"
	"github.com/spiffe/spiffe/workload"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
	. "gopkg.in/check.v1"
)

var (
	now     = time.Date(2015, 11, 16, 1, 2, 3, 0, time.UTC)
	aliceID = spiffe.MustParseID("urn:spiffe:example.com:user:alice")
	bobID   = spiffe.MustParseID("urn:spiffe:example.com:user:bob")
)

type WorkloadSuite struct {
	C     workload.Collections
	S     workload.Signer
	Clock clockwork.FakeClock
}

func (s *WorkloadSuite) WorkloadsCRUD(c *C) {
	w := workload.Workload{
		ID: "dev",
		Identities: []workload.ScopedID{
			{
				ID:        aliceID,
				MaxTTL:    time.Second,
				IsDefault: true,
			},
		},
		TrustedRootIDs: []string{"example.com"},
	}
	ctx := context.TODO()
	err := s.C.UpsertWorkload(ctx, w)
	c.Assert(err, IsNil)

	out, err := s.C.GetWorkload(ctx, w.ID)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, &w)

	err = s.C.DeleteWorkload(ctx, w.ID)
	c.Assert(err, IsNil)
}

func (s *WorkloadSuite) Events(c *C) {
	ctx, stopSubscribe := context.WithCancel(context.TODO())
	eventsC := make(chan *workload.WorkloadEvent, 100)
	err := s.C.Subscribe(ctx, eventsC)

	c.Assert(err, IsNil)
	w := workload.Workload{
		ID: "dev",
		Identities: []workload.ScopedID{
			{
				ID:        aliceID,
				MaxTTL:    time.Second,
				IsDefault: true,
			},
		},
		TrustedRootIDs: []string{"example.com"},
	}
	err = s.C.UpsertWorkload(ctx, w)
	c.Assert(err, IsNil)

	select {
	case e := <-eventsC:
		c.Assert(e, DeepEquals, &workload.WorkloadEvent{
			ID:       w.ID,
			Type:     workload.EventWorkloadUpdated,
			Workload: &w,
		})
	case <-time.After(time.Second):
		c.Fatal("timeout waiting for workload update")
	}

	err = s.C.DeleteWorkload(ctx, w.ID)
	c.Assert(err, IsNil)

	_, err = s.C.GetWorkload(ctx, w.ID)
	c.Assert(trace.IsNotFound(err), Equals, true)

	select {
	case e := <-eventsC:
		c.Assert(e, DeepEquals, &workload.WorkloadEvent{
			ID:   w.ID,
			Type: workload.EventWorkloadDeleted,
		})
	case <-time.After(time.Second):
		c.Fatal("timeout waiting for workload update")
	}

	stopSubscribe()

	select {
	case e := <-eventsC:
		c.Assert(e, IsNil)
	case <-time.After(time.Second):
		c.Fatal("timeout waiting for closed channel")
	}
}

func (s *WorkloadSuite) CertAuthoritiesCRUD(c *C) {
	ctx := context.TODO()
	ca := workload.CertAuthority{
		ID:         "example.com",
		Cert:       []byte(certAuthorityCertPEM),
		PrivateKey: []byte(certAuthorityKeyPEM),
	}
	err := s.C.UpsertCertAuthority(ctx, ca)
	c.Assert(err, IsNil)

	out, err := s.C.GetCertAuthority(ctx, ca.ID)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, &ca)

	err = s.C.DeleteCertAuthority(ctx, ca.ID)
	c.Assert(err, IsNil)

	_, err = s.C.GetCertAuthority(ctx, ca.ID)
	c.Assert(trace.IsNotFound(err), Equals, true)
}

func (s *WorkloadSuite) TrustedRootBundlesCRUD(c *C) {
	ctx := context.TODO()
	bundle := workload.TrustedRootBundle{
		ID: "prod",
		Certs: []workload.TrustedRootCert{{
			ID:   "example.com",
			Cert: []byte(certAuthorityCertPEM),
		}},
	}
	for i := 0; i < 600; i++ {
		bundle.Certs = append(bundle.Certs, workload.TrustedRootCert{
			ID:   "example.com",
			Cert: []byte(certAuthorityCertPEM),
		})
	}
	err := s.C.CreateTrustedRootBundle(ctx, bundle)
	c.Assert(err, IsNil)

	err = s.C.CreateTrustedRootBundle(ctx, bundle)
	c.Assert(trace.IsAlreadyExists(err), Equals, true, Commentf("%T", err))

	out, err := s.C.GetTrustedRootBundle(ctx, bundle.ID)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, &bundle)

	err = s.C.DeleteTrustedRootBundle(ctx, bundle.ID)
	c.Assert(err, IsNil)

	_, err = s.C.GetTrustedRootBundle(ctx, bundle.ID)
	c.Assert(trace.IsNotFound(err), Equals, true, Commentf("%T", err))
}

func (s *WorkloadSuite) PermissionsCRUD(c *C) {
	ctx := context.TODO()
	p1 := workload.Permission{
		ID:         bobID,
		Action:     workload.ActionCreate,
		Collection: workload.CollectionCertAuthorities,
	}

	out, err := s.C.GetPermission(ctx, p1)
	c.Assert(trace.IsNotFound(err), Equals, true, Commentf("%T", err))

	err = s.C.UpsertPermission(ctx, p1)
	c.Assert(err, IsNil)

	out, err = s.C.GetPermission(ctx, p1)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, &p1)

	p2 := workload.Permission{
		ID:           aliceID,
		Action:       workload.ActionUpdate,
		Collection:   workload.CollectionCertAuthorities,
		CollectionID: "2",
	}
	err = s.C.UpsertPermission(ctx, p2)
	c.Assert(err, IsNil)

	out, err = s.C.GetPermission(ctx, p2)
	c.Assert(out, DeepEquals, &p2)

	err = s.C.DeletePermission(ctx, p1)
	c.Assert(err, IsNil)
	_, err = s.C.GetPermission(ctx, p1)
	c.Assert(trace.IsNotFound(err), Equals, true, Commentf("%T"))

	err = s.C.DeletePermission(ctx, p2)
	c.Assert(err, IsNil)
	_, err = s.C.GetPermission(ctx, p2)
	c.Assert(trace.IsNotFound(err), Equals, true, Commentf("%T"))
}

func (s *WorkloadSuite) SignPermissionsCRUD(c *C) {
	ctx := context.TODO()
	s1 := workload.SignPermission{
		ID:              bobID,
		CertAuthorityID: "example.com",
		Org:             "a.example.com",
	}

	out, err := s.C.GetSignPermission(ctx, s1)
	c.Assert(trace.IsNotFound(err), Equals, true, Commentf("%T", err))

	err = s.C.UpsertSignPermission(ctx, s1)
	c.Assert(err, IsNil)

	out, err = s.C.GetSignPermission(ctx, s1)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, &s1)

	s2 := workload.SignPermission{
		ID:              aliceID,
		CertAuthorityID: "example.com",
		SignID:          &aliceID,
	}
	err = s.C.UpsertSignPermission(ctx, s2)
	c.Assert(err, IsNil)

	out, err = s.C.GetSignPermission(ctx, s2)
	c.Assert(out, DeepEquals, &s2)

	err = s.C.DeleteSignPermission(ctx, s1)
	c.Assert(err, IsNil)
	_, err = s.C.GetSignPermission(ctx, s1)
	c.Assert(trace.IsNotFound(err), Equals, true, Commentf("%T"))

	err = s.C.DeleteSignPermission(ctx, s2)
	c.Assert(err, IsNil)
	_, err = s.C.GetSignPermission(ctx, s2)
	c.Assert(trace.IsNotFound(err), Equals, true, Commentf("%T"))
}

func (s *WorkloadSuite) Signer(c *C) {
	ctx := context.TODO()
	ca := workload.CertAuthority{
		ID:         "example.com",
		Cert:       []byte(certAuthorityCertPEM),
		PrivateKey: []byte(certAuthorityKeyPEM),
	}
	err := s.C.UpsertCertAuthority(ctx, ca)
	c.Assert(err, IsNil)

	signer, err := workload.ParsePrivateKeyPEM([]byte(keyPEM))
	c.Assert(err, IsNil)
	extension, err := aliceID.X509Extension()
	c.Assert(err, IsNil)

	csr := &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{*extension},
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "*.example.com",
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, signer)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	re, err := s.S.ProcessCertificateRequest(ctx, workload.CertificateRequest{
		CertAuthorityID: ca.ID,
		CSR:             csrPEM,
		TTL:             time.Hour,
	})
	c.Assert(err, IsNil)

	cert, err := workload.ParseCertificatePEM(re.Cert)
	c.Assert(err, IsNil)
	c.Assert(cert, NotNil)

	c.Assert(cert.IsCA, Equals, false)
	c.Assert(cert.Subject.CommonName, DeepEquals, csr.Subject.CommonName)
	c.Assert(cert.Subject.Organization, DeepEquals, csr.Subject.Organization)

	ids, err := spiffe.IDsFromCertificate(cert)
	c.Assert(err, IsNil)
	c.Assert(ids, DeepEquals, []spiffe.ID{aliceID})
	c.Assert(cert.NotAfter, DeepEquals, s.Clock.Now().Add(time.Hour))
}

const (
	certAuthorityKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDB3SWxmlpEgX0S2LyOFc453q1Ah81wyFgScK1kHHFxPZIkYToAoavy3
93BF+Vh42kGgBwYFK4EEACKhZANiAAQ9zD7zchrwUchaOKLCqOaMfbF9lOAghTDh
c7fG+dzfqyAensEYv2kCwjChvkOSY98ICP6cI7uAxRa/jDEleH3jUWSW+4Zhjlr+
Sph6klSwp6OKAV7ZY1dD2hiPez8yOgo=
-----END EC PRIVATE KEY-----`

	certAuthorityCertPEM = `-----BEGIN CERTIFICATE-----
MIIC3zCCAmSgAwIBAgIUarbZ9SSSj5Dxf5uVGYpKOWMYmxgwCgYIKoZIzj0EAwMw
gawxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMSowKAYDVQQKEyFIb25lc3QgQWNobWVkJ3MgVXNlZCBDZXJ0
aWZpY2F0ZXMxKTAnBgNVBAsTIEhhc3RpbHktR2VuZXJhdGVkIFZhbHVlcyBEaXZp
c29uMRkwFwYDVQQDExBBdXRvZ2VuZXJhdGVkIENBMB4XDTE2MDkwOTE4MDEwMFoX
DTIxMDkwODE4MDEwMFowgawxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9y
bmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMSowKAYDVQQKEyFIb25lc3QgQWNo
bWVkJ3MgVXNlZCBDZXJ0aWZpY2F0ZXMxKTAnBgNVBAsTIEhhc3RpbHktR2VuZXJh
dGVkIFZhbHVlcyBEaXZpc29uMRkwFwYDVQQDExBBdXRvZ2VuZXJhdGVkIENBMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEPcw+83Ia8FHIWjiiwqjmjH2xfZTgIIUw4XO3
xvnc36sgHp7BGL9pAsIwob5DkmPfCAj+nCO7gMUWv4wxJXh941FklvuGYY5a/kqY
epJUsKejigFe2WNXQ9oYj3s/MjoKo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0T
AQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUWj02iLSGBt5+N/tWNT1la4fKu0cwCgYI
KoZIzj0EAwMDaQAwZgIxAM1olS0u60r//NCIcynnoXSjHi4IM/IO2YHJGtskikmC
4FUTH0tCg5SkqJ8ftRFvCgIxAKuqg9YJbzsU9S+H6MC+rudYK0tLbtmzyvm1+REG
xNrpWfzTahVFvuGne7dNcR+uZQ==
-----END CERTIFICATE-----`

	keyPEM = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAjToUX9qd4FxyQN51ZYHTqQQAMEJn7FGpwFF6KuH54dL1Bvx+HDHB5
b47UOMP6zAKgBwYFK4EEACKhZANiAARm+MJe+yEclPjJVs6QBfjMiW3xpArvOE/p
vA3hmMfkoEopFRen0K7KCZNNDFyTbsn5Ven93m+6UBYm11imhzmBdqnmB9IzVrRc
JXqTTFIkw/bap1cy2hlfLNdk9njzy/0=
-----END EC PRIVATE KEY-----`
)
