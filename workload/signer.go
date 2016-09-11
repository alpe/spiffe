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

func (c *CertSigner) ProcessCertificateRequest(ctx context.Context, req CertificateRequest) ([]byte, error) {
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

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
}
