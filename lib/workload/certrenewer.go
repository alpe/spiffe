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
	"crypto/x509/pkix"
	"encoding/pem"
	"sync"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
)

// CertificateRequestTemplate is a helper struct to hold
// parameters necessary to generate proper certificate request
type CertificateRequestTemplate struct {
	CertAuthorityID string
	ID              identity.ID
	Subject         pkix.Name
	DNSNames        []string
	KeyPEM          []byte
	TTL             time.Duration
}

// Check checks parameters of the template
func (t *CertificateRequestTemplate) Check() error {
	if t.CertAuthorityID == "" {
		return trace.BadParameter("missing parameter CertAuthorityID")
	}
	if err := t.ID.Check(); err != nil {
		return trace.Wrap(err)
	}
	if t.TTL <= 0 {
		return trace.BadParameter("missing parameter TTL")
	}
	return nil
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

// NewMemStorage returns new instance of memory backed storage
func NewMemStorage() *MemStorage {
	return &MemStorage{
		vals: make(map[string][]byte),
	}
}

// MemStorage implements helper in-memory storage
type MemStorage struct {
	sync.Mutex
	vals map[string][]byte
}

func (m *MemStorage) ReadPath(path string) ([]byte, error) {
	m.Lock()
	defer m.Unlock()
	val, ok := m.vals[path]
	if !ok {
		return nil, trace.NotFound("%v not found", path)
	}
	return val, nil
}

func (m *MemStorage) WritePath(path string, data []byte) error {
	m.Lock()
	defer m.Unlock()
	m.vals[path] = data
	return nil
}

// KeyPairReader specifies method to read keypair from storage
type KeyPairReader func() (*KeyPair, error)

// KeyPairWriter specifies a method to write files to storage
type KeyPairWriter func(KeyPair) error

// KeyPair contains renewed certificate and private key
type KeyPair struct {
	// CertPEM is a PEM encoded certificate
	CertPEM []byte
	// KeyPEM is a PEM encoded private key
	KeyPEM []byte
	// CAPEM is a PEM file with certificate of the certificate authority
	CAPEM []byte
}

// CertRenewerConfig configures certificate renewer
type CertRenewerConfig struct {
	Clock clockwork.Clock
	// Template specifies certificate parameters
	Template CertificateRequestTemplate
	// Service is a workload service
	Service Service
	// ReadKey is used to read private keypair from storage
	ReadKeyPair KeyPairReader
	// WriteKey is used to write back the newly generated private key
	WriteKeyPair KeyPairWriter
	// EventsC is a channel for notifications about renewed certifictes
	EventsC chan *KeyPair
	// Entry is a logger entry
	Entry *log.Entry
}

// CheckAndSetDefaults checks config params and sets some default values
func (c *CertRenewerConfig) CheckAndSetDefaults() error {
	if err := c.Template.Check(); err != nil {
		return trace.Wrap(err)
	}
	if c.Service == nil {
		return trace.BadParameter("missing parmeter Service")
	}
	if c.ReadKeyPair == nil {
		return trace.BadParameter("missing parameter ReadKeyPair")
	}
	if c.WriteKeyPair == nil {
		return trace.BadParameter("missing parameter WriteKeyPair")
	}
	if c.Entry == nil {
		return trace.BadParameter("missing parameter Entry")
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	return nil
}

// CertRenewer takes care of certificate periodic renewal - it monitors
// certificates TTL and requests new certificates when they are about to
// expire.
type CertRenewer struct {
	*log.Entry
	CertRenewerConfig
}

// NewCertRenewer returns new instance of certificate renewer
func NewCertRenewer(config CertRenewerConfig) (*CertRenewer, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &CertRenewer{
		CertRenewerConfig: config,
		Entry:             config.Entry,
	}, nil
}

func (r *CertRenewer) tickPeriod() time.Duration {
	return (r.Template.TTL * 3) / 4
}

func (r *CertRenewer) renewTrigger() time.Duration {
	return r.Template.TTL / 2
}

func (r *CertRenewer) watch(ctx context.Context) error {
	eventsC := make(chan *Event, 1)
	subscribeContext, cancelWatch := context.WithCancel(ctx)
	err := r.Service.Subscribe(subscribeContext, eventsC)
	if err != nil {
		return trace.Wrap(err)
	}
	defer cancelWatch()

	ticker := time.NewTicker(r.tickPeriod())
	defer ticker.Stop()
	for {
		select {
		case event := <-eventsC:
			if event == nil {
				return trace.ConnectionProblem(nil, "server disconnected")
			}
			if event.Type == EventTypeCertAuthority && event.ID == r.Template.CertAuthorityID {
				if event.Action == EventActionDeleted {
					r.Debugf("CertAuthority %v signing this certificate vanished, stop signing process", r.Template.CertAuthorityID)
					return nil
				} else if event.Action == EventActionUpdated {
					r.Debugf("CertAuthority %v signing this certificate updated, renew the certificate", r.Template.CertAuthorityID)
					err := r.Renew(ctx)
					if err != nil {
						return trace.Wrap(err)
					}
				}
			}
		case <-ticker.C:
			err := r.Renew(ctx)
			if err != nil {
				return trace.Wrap(err)
			}
		case <-ctx.Done():
			r.Debugf("context is closing, returning")
			return nil
		}
	}
}

// Start starts renewer procedure, it is a blocking call,
// to cancel, simply use context cancelling ability
func (r *CertRenewer) Start(ctx context.Context) error {
	err := r.Renew(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	for {
		err = r.watch(ctx)
		if err != nil {
			if !trace.IsConnectionProblem(err) {
				r.Error(trace.DebugReport(err))
				return trace.Wrap(err)
			}
			r.Debugf("connection problem while connecting, restart in %v", constants.DefaultReconnectPeriod)
			select {
			case <-time.After(constants.DefaultReconnectPeriod):
			case <-ctx.Done():
				r.Debugf("context is closing")
				return nil
			}
		}
	}
}

func (r *CertRenewer) Renew(ctx context.Context) error {
	keyPair, err := r.ReadKeyPair()
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		keyPair = &KeyPair{}
		r.Debugf("keypair is not found, generate a new one")
		keyPair.KeyPEM, err = identity.GenerateRSAPrivateKeyPEM()
		if err != nil {
			return trace.Wrap(err)
		}
	}

	ca, err := r.Service.GetCertAuthorityCert(ctx, r.Template.CertAuthorityID)
	if err != nil {
		return trace.Wrap(err)
	}

	caCert, err := ParseCertificatePEM(ca.Cert)
	if err != nil {
		return trace.Wrap(err)
	}

	if len(keyPair.CertPEM) != 0 {
		cert, err := ParseCertificatePEM(keyPair.CertPEM)
		if err != nil {
			return trace.Wrap(err)
		}
		if err := cert.CheckSignatureFrom(caCert); err == nil {
			diff := cert.NotAfter.Sub(r.Clock.Now())
			if diff > r.renewTrigger() {
				r.Debugf("cert is present and expires %v (in %v), still good", cert.NotAfter, diff)
				return nil
			}
			r.Debugf("cert is present, but expires %v (in %v)", cert.NotAfter, diff)
		} else {
			r.Debugf("cert signature does not verify: %v", err.Error())
		}
	}

	r.Debugf("going to generate a new certificate")
	r.Template.KeyPEM = keyPair.KeyPEM
	csr, err := CreateCertificateRequest(r.Template)
	if err != nil {
		return trace.Wrap(err)
	}
	re, err := r.Service.ProcessCertificateRequest(ctx, *csr)
	if err != nil {
		return trace.Wrap(err)
	}
	keyPair.CertPEM = re.Cert

	keyPair.CAPEM = ca.Cert

	if err := r.WriteKeyPair(*keyPair); err != nil {
		return trace.Wrap(err)
	}

	if r.EventsC != nil {
		select {
		case r.EventsC <- keyPair:
			return nil
		default:
			return trace.ConnectionProblem(nil, "failed to send event")
		}
	}
	return nil
}
