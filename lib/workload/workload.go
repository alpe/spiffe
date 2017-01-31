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

// package workload defines SPIFFE workload API
package workload

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spiffe/spiffe/lib/identity"

	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

// CertAuthority represents an authority that this server is representing.
type CertAuthority struct {
	// ID is a unique identifier of the authority, usually SPIFFE org name
	ID string
	// Cert is a PEM-encoded certificate of the certificate signing authority
	Cert []byte
	// PrivateKey is PEM-encoded private key of the certificate signing authority
	PrivateKey []byte
}

func (c *CertAuthority) ParsedCertificate() (*x509.Certificate, error) {
	if len(c.Cert) == 0 {
		return nil, trace.BadParameter("missing parameter Cert")
	}
	return ParseCertificatePEM(c.Cert)
}

func (c *CertAuthority) ParsedPrivateKey() (crypto.Signer, error) {
	if len(c.PrivateKey) == 0 {
		return nil, trace.BadParameter("missing parameter PrivateKey")
	}
	return ParsePrivateKeyPEM(c.PrivateKey)
}

func (c *CertAuthority) Check() error {
	if c.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}

	_, err := c.ParsedCertificate()
	if err != nil {
		return trace.Wrap(err)
	}

	if len(c.PrivateKey) != 0 {
		if _, err := c.ParsedPrivateKey(); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// Authorities manages certificate authorities
type Authorities interface {
	// CreateCertAuthority creates cert authority if it does not exist
	CreateCertAuthority(ctx context.Context, ca CertAuthority) error
	// UpsertCertAuthority updates or inserts certificate authority
	// In case if CA can sign, Private
	UpsertCertAuthority(ctx context.Context, ca CertAuthority) error
	// GetCertAuthority returns Certificate Authority by given ID
	GetCertAuthority(ctx context.Context, id string) (*CertAuthority, error)
	// GetCertAuthorityCert returns Certificate Authority (only certificate) by it's ID
	GetCertAuthorityCert(ctx context.Context, id string) (*CertAuthority, error)
	// DeleteCertAuthority deletes Certificate Authority by ID
	DeleteCertAuthority(ctx context.Context, id string) error
	// GetCertAuthoritiesCerts returns a list of certificate authorities
	GetCertAuthoritiesCerts(ctx context.Context) ([]CertAuthority, error)
}

// TrustedRootBundle is a collection of trusted roots grouped together
// lots of certs are grouped together
type TrustedRootBundle struct {
	// ID is id of the trusted root bundle
	ID string
	// Certs is a list of external certificates to trust
	Certs []TrustedRootCert
	// CertAuthorityIDs is a list of certificate authorities to trust
	CertAuthorityIDs []string
}

// Check checks root bundle
func (b *TrustedRootBundle) Check() error {
	if b.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}
	for _, c := range b.Certs {
		if err := c.Check(); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// TrustedRootCert represents trusted root x509 certificate authority certificate
type TrustedRootCert struct {
	// ID is a unique certificate ID
	ID string
	// Filename is how this root will be stored on the filesystem,
	// if omitted, will use ID as the filename
	Filename string
	// Cert is PEM-encoded trusted cert bytes
	Cert []byte
}

// ParsedCertificate returns parsed certificate
func (r *TrustedRootCert) ParsedCertificate() (*x509.Certificate, error) {
	if len(r.Cert) == 0 {
		return nil, trace.BadParameter("missing parameter Cert")
	}
	return ParseCertificatePEM(r.Cert)
}

func (r *TrustedRootCert) Check() error {
	if r.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}
	if _, err := r.ParsedCertificate(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// TrustedRootBundles manages collection trusted root certificates
type TrustedRootBundles interface {
	// CreateTrustedRootBundle creates trusted root certificate bundle
	CreateTrustedRootBundle(ctx context.Context, bundle TrustedRootBundle) error
	// UpsertTrustedRootBundle creates or updates trusted root certificate bundle
	UpsertTrustedRootBundle(ctx context.Context, bundle TrustedRootBundle) error
	// GetTrustedRoot returns trusted root certificate by its ID
	GetTrustedRootBundle(ctx context.Context, id string) (*TrustedRootBundle, error)
	// DeleteTrustedRootBundle deletes TrustedRoot by its ID
	DeleteTrustedRootBundle(ctx context.Context, id string) error
	// GetTrustedRootBundles returns a list of trusted root bundles
	GetTrustedRootBundles(ctx context.Context) ([]TrustedRootBundle, error)
}

// ScopedID represents SPIFFE ID with attached
// scope of usage (limits Max TTL for certificate issued)
type ScopedID struct {
	// ID is a SPIFFE ID
	ID identity.ID
	// MaxTTL sets up maximum TTL for the signed cert for this workload
	MaxTTL time.Duration
	// IsDefault sets up this ID as a default id for the workload
	IsDefault bool
}

// Workload represents SPIFFE workload - a set of SPIFFE ids
type Workload struct {
	// ID is a unique workload ID
	ID string
	// Identities is a list of SPIFFE ids associated with this workload
	Identities []ScopedID
	// TrustedBundleIDs is a list of IDs of trusted root certificate bundles assigned
	// to this workload. NodeCA will use this list to update trusted roots
	// of SPIFFE-powered servers and clients
	TrustedBundleIDs []string
}

// Check checks whether all workload params are valid
func (w *Workload) Check() error {
	if w.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}
	if len(w.Identities) == 0 {
		return trace.BadParameter("missing parameter Identities")
	}
	for _, id := range w.Identities {
		if err := id.ID.Check(); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// Event represents a change on either workload, certificate authority or trusted root bundle
type Event struct {
	// ID is a unique workload ID
	ID string
	// Type is event type, see `EventTypeWorkload*` group of events
	Type string
	// Action specifies action on the element, see `EventAction*`  group of events
	Action string
	// Workload, In case if workload was updated, will contain the new version
	Workload *Workload
	// TrustedRootBundle will be populated if it was updated
	Bundle *TrustedRootBundle
	// CertAuthority will contain only public certificate of the updated authority
	CertAuthority *CertAuthority
}

// String returns user-friendly event description
func (e *Event) String() string {
	return fmt.Sprintf("event(id=%v, action=%v, type=%v)", e.ID, e.Action, e.Type)
}

const (
	// EventTypeWorkload indicates that this is event about workload
	EventTypeWorkload = "EventWorkload"
	// EventTypeWorkload indicates that this is event about trusted root bundle
	EventTypeTrustedRootBundle = "EventTrustedRootBundle"
	// EventTypeCertAuthority indicates that this event about certificate authority
	EventTypeCertAuthority = "EventCertAuthority"
	// EventActionUpdated - element has been updated on the server
	EventActionUpdated = "Updated"
	// EventActionDeleted - element has been deleted from the server
	EventActionDeleted = "Deleted"
)

// Subscriber adds ability to subscribe to a list of events with cluster updates
type Subscriber interface {
	// Subscribe returns a stream of events associated with given workload IDs
	// if you wish to cancel the stream, use ctx.Close
	// eventC will be closed by Subscribe function on errors or
	// cancelled subscribe
	Subscribe(ctx context.Context, eventC chan *Event) error
}

// Workloads is a SPIFFE workload API
type Workloads interface {
	// UpsertWorkload update existing or insert new workload
	UpsertWorkload(ctx context.Context, w Workload) error
	// DeleteWorkload deletes workload
	DeleteWorkload(ctx context.Context, ID string) error
	// GetWorkload returns workload identified by ID
	GetWorkload(ctx context.Context, ID string) (*Workload, error)
	// GetWorkloads returns a list of workloads in the system
	GetWorkloads(ctx context.Context) ([]Workload, error)
}

// CertificateRequest is a request to sign a CSR by a particular certificate
// authority
type CertificateRequest struct {
	// CertAuthorityID is the ID of the certificate authority that
	// should sign the certificate
	CertAuthorityID string
	// TTL is the desired TTL of the certificate. May be rejected if permissions
	// do not allow the requested TTL
	TTL time.Duration
	// CSR is a certificate signing request PEM bytes
	CSR []byte
}

// Check checks parameters for missing parmaeters
func (c *CertificateRequest) Check() error {
	if c.CertAuthorityID == "" {
		return trace.BadParameter("missing parameter CertAuthorityID")
	}
	if c.TTL == 0 {
		return trace.BadParameter("missing parameter TTL")
	}
	if len(c.CSR) == 0 {
		return trace.BadParameter("missing parameter CSR")
	}
	return nil
}

// CertificateResponse is returned by Signer
type CertificateResponse struct {
	// Cert is a PEM byte array with signed certificate
	Cert []byte
}

// Signer is a workload-aware certificate signer.
// For example to generate CSR for SPIFFE ID 'urn:spiffe:example.com:opaque:id'
// and workload 'dev', NodeCA will produce CSR with the following fields set:
//   * SubjectCommonName: example.com
//   * SubjectAltName: urn:spiffe:example.com:opaque.id
//
// Workload Server will:
//
// * Make sure that workload 'dev' has assigned SPIFFE id `urn:spiffe:example.com:opaque.id`
// * Fetch CertAuthority with ID `example.com`
// * Use it to process CSR with TTL <= MaxTTL in the ScopedID of the workload
type Signer interface {
	// ProcessCertificateRequest process x509 CSR to sign with particular TTL and specifies which CertificateAuthority to use
	ProcessCertificateRequest(ctx context.Context, req CertificateRequest) (*CertificateResponse, error)
}

// PermissionsReader implements read-only access to permissions collection
type PermissionsReader interface {
	// GetSignPermission return permission for actor identified by SPIFFE ID
	GetSignPermission(ctx context.Context, sp SignPermission) (*SignPermission, error)
	// GetPermission returns permission for actor identified by SPIFFE ID
	GetPermission(ctx context.Context, p Permission) (*Permission, error)
}

// Permissions controls collection with permissions
type Permissions interface {
	PermissionsReader
	// UpsertPermission updates or inserts permission for actor identified by SPIFFE ID
	UpsertPermission(ctx context.Context, p Permission) error
	// DeletePermission deletes permission
	DeletePermission(ctx context.Context, p Permission) error
	// UpsertSignPermission updates or inserts permission for actor identified by SPIFFE ID
	UpsertSignPermission(ctx context.Context, p SignPermission) error
	// DeleteSignPermission deletes sign permission
	DeleteSignPermission(ctx context.Context, sp SignPermission) error
}

// Permission grants some actor identified by SPIFFE ID permssion to
// execute some action. Reads as:
// This actor with identifier ID can Action on Collection with element CollectionID
type Permission struct {
	ID identity.ID
	// Action  is the action that this
	Action string
	// Collection represents some stored collection of elements
	Collection string
	// CollectionID, if specified limits the scope
	CollectionID string
}

// String returns human-readable permission
func (p Permission) String() string {
	return fmt.Sprintf("Permission(id=%v, action=%v, collection=%v, collectionID=%v)", p.ID, p.Action, p.Collection, p.CollectionID)
}

// Check checks whether permission is valid
func (p *Permission) Check() error {
	if err := p.ID.Check(); err != nil {
		return trace.Wrap(err)
	}
	switch p.Action {
	case ActionRead, ActionUpsert, ActionCreate, ActionDelete, ActionReadPublic:
	case "":
		return trace.BadParameter("missing parameter Action")
	default:
		return trace.BadParameter("unsupported Action: '%v'", p.Action)
	}
	if p.Collection == "" {
		return trace.BadParameter("missing parameter Collection")
	}
	return nil
}

const (
	// ActionRead lets to read all the data, private and public
	ActionRead = "read"
	// ActionReadPublic lets to read only public parts of some data, e.g. certificates
	// of certificate authorities, not their private keys
	ActionReadPublic = "readpub"
	// ActionUpsert allows to upsert elements - create and update them
	ActionUpsert = "upsert"
	// ActionCreate allows to create elements
	ActionCreate = "create"
	// ActionDelete allows to delete elements
	ActionDelete = "delete"
)

const (
	// CollectionWorkloads represents collection of workloads
	CollectionWorkloads = "workloads"
	// CollectionTrustedRootBundles is a collection with trusted root certificate bundles
	CollectionTrustedRootBundles = "rootbundles"
	// CollectionCertAuthorities is a collection with certificate authorities
	CollectionCertAuthorities = "authorities"
	// CollectionPermissions controls collection with permissions
	CollectionPermissions = "permissions"
	// CollectionSignPermissions controls collection with sign permissions
	CollectionSignPermissions = "signpermissions"
)

// SignPermission reads as:
// this ID can generate certificates for organisation Org and SPIFFE ids IDs
// using certificate authority CertAuthorityID
type SignPermission struct {
	ID identity.ID
	// CertAuthorityID if present allows signing using particular certificate authority ID
	CertAuthorityID string
	// Org if present, limits generating CSRs to get certificates for paricular org name
	// TODO(klizhentas) rename this to CommonName
	Org string
	// SignIDs if present, limits using signing for particular SPIFFE ID
	SignID *identity.ID
	// MaxTTL controls maximum TTL of the issued certificate
	MaxTTL time.Duration
}

// String returns sign permission debug info
func (s SignPermission) String() string {
	return fmt.Sprintf("SignPermission(ID=%v, CertAuthorityID=%v, CommonName=%v, SignID=%v, TTL=%v)",
		s.ID, s.CertAuthorityID, s.Org, s.SignID, s.MaxTTL)
}

// Check checks whether sign permission parameters are valid
func (p *SignPermission) Check() error {
	if err := p.ID.Check(); err != nil {
		return trace.Wrap(err)
	}
	if p.SignID != nil {
		if err := p.SignID.Check(); err != nil {
			return trace.Wrap(err, "error verifying %v", p.SignID)
		}
	}
	return nil
}

// Collections manages stored collections - Workloads, Permissions, Authorities and TrustedRootBundles
type Collections interface {
	Permissions
	TrustedRootBundles
	Authorities
	Workloads
	Subscriber
}

// Service is a full implementaion of workload service
type Service interface {
	Collections
	Signer
}
