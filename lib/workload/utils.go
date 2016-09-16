package workload

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"sync"
	"time"

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

// FileReader specifies method to read file from storage
type FileReader func() ([]byte, error)

// FileWriter specifies a method to write files to storage
type FileWriter func([]byte) error

// RenewedKeyPair contains renewed certificate and private key
type RenewedKeyPair struct {
	// CertPEM is a PEM encoded certificate
	CertPEM []byte
	// KeyPEM is a PEM encoded private key
	KeyPEM []byte
}

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
	EventsC chan *RenewedKeyPair
	// Entry is a logger entry
	Entry *log.Entry
}

// Renewer takes care of certificate periodic renewal - it monitors
// certificates TTL and requests new certificates when they are about to
// expire.
type Renewer struct {
	*log.Entry
	RenewerConfig
}

// NewRenewer returns new instance of renewer
func NewRenewer(config RenewerConfig) (*Renewer, error) {
	return &Renewer{
		RenewerConfig: config,
		Entry:         config.Entry,
	}, nil
}

func (r *Renewer) tickPeriod() time.Duration {
	return (r.Template.TTL * 3) / 4
}

func (r *Renewer) renewTrigger() time.Duration {
	return r.Template.TTL / 2
}

// Start starts renewer procedure, it is a blocking call,
// to cancel, simply use context cancelling ability
func (r *Renewer) Start(ctx context.Context) error {
	err := r.Renew(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	ticker := time.NewTicker(r.tickPeriod())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := r.Renew(ctx)
			if err != nil {
				return trace.Wrap(err)
			}
		case <-ctx.Done():
			r.Debugf("context is closing, returning", r)
			return nil
		}
	}
}

func (r *Renewer) Renew(ctx context.Context) error {
	keyPEM, err := r.ReadKey()
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		r.Debugf("key is not found, generate a new one")
		keyPEM, err = identity.GenerateRSAPrivateKeyPEM()
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
		diff := cert.NotAfter.Sub(r.Clock.Now())
		if diff > r.renewTrigger() {
			r.Debugf("cert is present and expires %v (in %v), still good", cert.NotAfter, diff)
			return nil
		} else {
			r.Debugf("cert is present, but expires %v (in %v)", cert.NotAfter, diff)
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
		case r.EventsC <- &RenewedKeyPair{CertPEM: re.Cert, KeyPEM: keyPEM}:
			return nil
		default:
			return trace.ConnectionProblem(nil, "failed to send event")
		}
	}
	return nil
}

// SetAdminPermissions sets admin permissions for identity ID
func SetAdminPermissions(ctx context.Context, service Permissions, id identity.ID, signTTL time.Duration) error {
	permissions := []Permission{
		// authorities
		{ID: id, Action: ActionUpsert, Collection: CollectionCertAuthorities},
		{ID: id, Action: ActionRead, Collection: CollectionCertAuthorities},
		{ID: id, Action: ActionDelete, Collection: CollectionCertAuthorities},

		// workloads
		{ID: id, Action: ActionUpsert, Collection: CollectionWorkloads},
		{ID: id, Action: ActionRead, Collection: CollectionWorkloads},
		{ID: id, Action: ActionDelete, Collection: CollectionWorkloads},

		// root bundles
		{ID: id, Action: ActionUpsert, Collection: CollectionTrustedRootBundles},
		{ID: id, Action: ActionRead, Collection: CollectionTrustedRootBundles},
		{ID: id, Action: ActionDelete, Collection: CollectionTrustedRootBundles},

		// permissions
		{ID: id, Action: ActionUpsert, Collection: CollectionPermissions},
		{ID: id, Action: ActionRead, Collection: CollectionPermissions},
		{ID: id, Action: ActionDelete, Collection: CollectionPermissions},

		// sign permissions
		{ID: id, Action: ActionUpsert, Collection: CollectionSignPermissions},
		{ID: id, Action: ActionRead, Collection: CollectionSignPermissions},
		{ID: id, Action: ActionDelete, Collection: CollectionSignPermissions},
	}
	for _, p := range permissions {
		if err := service.UpsertPermission(ctx, p); err != nil {
			return trace.Wrap(err)
		}
	}

	signPermissions := []SignPermission{
		{ID: id, MaxTTL: signTTL},
	}
	for _, sp := range signPermissions {
		if err := service.UpsertSignPermission(ctx, sp); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}
