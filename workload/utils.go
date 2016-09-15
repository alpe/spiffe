package workload

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/spiffe/spiffe"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
)

// CertificateRequestTemplate is a helper struct to hold
// parameters necessary to generate proper certificate request
type CertificateRequestTemplate struct {
	CertAuthorityID string
	ID              spiffe.ID
	Subject         pkix.Name
	DNSNames        []string
	KeyPEM          []byte
	TTL             time.Duration
}

// CrateCertificateRequest generates proper CSR with for particular SPIFFE ID
func CreateCertificateRequest(template CertificateRequestTemplate) (*CertificateRequest, error) {
	signer, err := ParsePrivateKeyPEM(template.KeyPEM)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	extension, err := template.ID.X509Extension()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	csr := &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{*extension},
		Subject:         template.Subject,
		DNSNames:        template.DNSNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, signer)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return &CertificateRequest{
		CertAuthorityID: template.CertAuthorityID,
		CSR:             csrPEM,
		TTL:             template.TTL,
	}, nil
}

// FileReader specifies method to read file from storage
type FileReader func() ([]byte, error)

// FileWriter specifies a method to write files to storage
type FileWriter func([]byte) error

// RenewerConfig configures certificate renewer
type RenewerConfig struct {
	Clock clockwork.Clock
	// Template specifies certificate parameters
	Template CertificateRequestTemplate
	// Signer is a local or remote signing signer
	Signer Signer
	// ReadKey is used to read private key from storage
	ReadKey FileReader
	// ReadCert is used to read certificate from storage
	ReadCert FileReader
	// WriteKey is used to write back the newly generated private key
	WriteKey FileWriter
	// CertWriter is used to write back the newly signed certificate
	WriteCert FileWriter
	// EventsC is a channel for notifications about renewed certifictes
	EventsC chan []byte
	// Entry is a logger entry
	Entry *log.Entry
}

type Renewer struct {
	*log.Entry
	RenewerConfig
}

func NewRenewer(config RenewerConfig) (*Renewer, error) {
	return &Renewer{
		RenewerConfig: config,
		Entry:         config.Entry,
	}, nil
}

func (r *Renewer) Renew(ctx context.Context) error {
	keyPEM, err := r.ReadKey()
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		r.Debugf("key is not found, generate a new one")
		keyPEM, err = spiffe.GenerateRSAPrivateKeyPEM()
		if err != nil {
			return trace.Wrap(err)
		}
		err = r.WriteKey(keyPEM)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	certPEM, err := r.ReadCert()
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	} else {
		cert, err := ParseCertificatePEM(certPEM)
		if err != nil {
			return trace.Wrap(err)
		}
		diff := r.Clock.Now().Sub(cert.NotAfter)
		if diff > r.Template.TTL/10 {
			r.Debugf("cert is present and expires in %v, still good", cert.NotAfter)
			return nil
		} else {
			r.Debugf("cert is present, but expires in %v")
		}
	}

	r.Debugf("going to generate a new certificate")
	r.Template.KeyPEM = keyPEM
	csr, err := CreateCertificateRequest(r.Template)
	if err != nil {
		return trace.Wrap(err)
	}
	re, err := r.Signer.ProcessCertificateRequest(ctx, *csr)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := r.WriteCert(re.Cert); err != nil {
		return trace.Wrap(err)
	}

	if r.EventsC != nil {
		select {
		case r.EventsC <- re.Cert:
			return nil
		default:
			return trace.ConnectionProblem(nil, "failed to send event")
		}
	}
	return nil
}
