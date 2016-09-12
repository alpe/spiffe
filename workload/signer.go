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

package workload

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
)

// CertSigned uses access to stored data
// to process certificate signing requests
type CertSigner struct {
	Collections
	clockwork.Clock
}

func (c *CertSigner) ProcessCertificateRequest(ctx context.Context, req CertificateRequest) (*CertificateResponse, error) {
	csr, err := ParseCertificateRequestPEM(req.CSR)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certAuthority, err := c.GetCertAuthority(ctx, req.CertAuthorityID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certAuthorityCert, err := certAuthority.ParsedCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certAuthorityKey, err := certAuthority.ParsedPrivateKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	notBefore := c.Now().UTC()
	notAfter := notBefore.Add(req.TTL)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	template := &x509.Certificate{
		ExtraExtensions:       csr.Extensions,
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, // no intermediate certs allowed
		IsCA: false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, certAuthorityCert, csr.PublicKey, certAuthorityKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &CertificateResponse{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}),
	}, nil
}
