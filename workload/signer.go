package workload

import (
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

// CertSigned uses access to stored data
// to process certificate signing requests
type CertSigner struct {
	Collections
}

func (c *CertSigner) ProcessCSR(ctx context.Context, reqData []byte) ([]byte, error) {
	req, err := ParseCertificateRequestPEM(reqData)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req.Subject.CommonName

	if req.CAConstraint.IsCA {
		return nil, trace.BadParameter("can not create CA certificate")
	}

}
