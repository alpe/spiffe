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
	"time"

	"github.com/spiffe/spiffe"

	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

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
	// UpsertCertAuthority updates or inserts certificate authority
	// In case if CA can sign, Private
	UpsertCertAuthority(ctx context.Context, ca CertAuthority) error
	// GetCertAuthority returns Certificate Authority by given ID
	GetCertAuthority(ctx context.Context, id string) (*CertAuthority, error)
	// DeleteCertAuthority deletes Certificate Authority by ID
	DeleteCertAuthority(ctx context.Context, id string) error
}

// TrustedRoot represents trusted root x509 certificate authority certificate
type TrustedRoot struct {
	// ID is a unique certificate ID
	ID string
	// Cert is PEM-encoded trusted cert bytes
	Cert []byte
}

// ParsedCertificate returns parsed certificate
func (r *TrustedRoot) ParsedCertificate() (*x509.Certificate, error) {
	if len(r.Cert) == 0 {
		return nil, trace.BadParameter("missing parameter Cert")
	}
	return ParseCertificatePEM(r.Cert)
}

func (r *TrustedRoot) Check() error {
	if r.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}
	if _, err := r.ParsedCertificate(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// TrustedRoots manages collection trusted root certificates
type TrustedRoots interface {
	// UpsertTrustedRoot updates or insert trusted root certificate
	UpsertTrustedRoot(ctx context.Context, root TrustedRoot) error
	// GetTrustedRoot returns trusted root certificate by its ID
	GetTrustedRoot(ctx context.Context, id string) (*TrustedRoot, error)
	// DeleteTrustedRoot deletes TrustedRoot by its ID
	DeleteTrustedRoot(ctx context.Context, id string) error
}

// ScopedID represents SPIFFE ID with attached
// scope of usage (limits Max TTL for certificate issued)
type ScopedID struct {
	// ID is a SPIFFE ID
	ID spiffe.ID
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
	// TrustedRootIDs is a list of IDs of trusted root certificates assigned
	// to this workload. NodeCA will use this list to update trusted roots
	// of SPIFFE-powered servers and clients
	TrustedRootIDs []string
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

// WorkloadEvent represents any change to a given workload
type WorkloadEvent struct {
	// ID is a unique workload ID
	ID string
	// Type is event type, see `EventWorkload*` family of events for details
	Type string
	// In case if workload was updated, will contain the new version
	Workload *Workload
}

const (
	// EventWorkloadUpdated - workload has been updated on the server
	EventWorkloadUpdated = "WorkloadUpdated"
	// EventWorkloadDeleted - workload has been deleted from the server
	EventWorkloadDeleted = "WorkloadDeleted"
)

// Workloads is a SPIFFE workload API
type Workloads interface {
	// UpsertWorkload update existing or insert new workload
	UpsertWorkload(ctx context.Context, w Workload) error
	// DeleteWorkload deletes workload
	DeleteWorkload(ctx context.Context, ID string) error
	// GetWorkload returns workload identified by ID
	GetWorkload(ctx context.Context, ID string) (*Workload, error)
	// Subscribe returns a stream of events associated with given workload IDs
	// if you wish to cancel the stream, use ctx.Close
	// eventC will be closed by Subscribe function on errors or
	// cancelled subscribe
	Subscribe(ctx context.Context, eventC chan *WorkloadEvent) error
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
	ProcessCSR(ctx context.Context, req x509.CertificateRequest) (x509.Certificate, error)
}

// Permissions controls collection with permissions
type Permissions interface {
	// UpsertPermission updates or inserts permission for actor identified by SPIFFE ID
	UpsertPermission(ctx context.Context, p Permission) error
	// GetPermission returns permission for actor identified by SPIFFE ID
	GetPermission(ctx context.Context, p Permission) (*Permission, error)
	// DeletePermission deletes permission
	DeletePermission(ctx context.Context, p Permission) error
	// UpsertSignPermission updates or inserts permission for actor identified by SPIFFE ID
	UpsertSignPermission(ctx context.Context, p SignPermission) error
	// GetSignPermission return permission for actor identified by SPIFFE ID
	GetSignPermission(ctx context.Context, sp SignPermission) (*SignPermission, error)
	// DeleteSignPermission deletes sign permission
	DeleteSignPermission(ctx context.Context, sp SignPermission) error
}

// Permission grants some actor identified by SPIFFE ID permssion to
// execute some action. Reads as:
// This actor with identifier ID can Action on Collection with element CollectionID
type Permission struct {
	ID spiffe.ID
	// Action  is the action that this
	Action string
	// Collection represents some stored collection of elements
	Collection string
	// CollectionID, if specified limits the scope
	CollectionID string
}

// Check checks whether permission is valid
func (p *Permission) Check() error {
	if err := p.ID.Check(); err != nil {
		return trace.Wrap(err)
	}
	switch p.Action {
	case ActionRead, ActionUpdate, ActionCreate, ActionDelete:
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
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionCreate = "create"
	ActionDelete = "delete"
)

const (
	// CollectionWorkloads represents collection of workloads
	CollectionWorkloads = "workloads"
	// CollectionTrustedRoots is a collection with trusted root certificates
	CollectionTrustedRoots = "roots"
	// CollectionCertAuthorities is a collection with certificate
	CollectionCertAuthorities = "authorities"
	// CollectionPermissions controls collection with permissions
	CollectionPermissions = "permissions"
)

// SignPermission reads as:
// this ID can generate certificates for organisation Org and SPIFFE ids IDs
// using certificate authority CertAuthorityID
type SignPermission struct {
	ID spiffe.ID
	// CertAuthorityID if present allows signing using particular certificate authority ID
	CertAuthorityID string
	// Org if present, limits generating CSRs to get certificates for paricular org name
	Org string
	// SignID if present, limits using signing for particular SpiffeID
	SignID *spiffe.ID
}

// Check checks whether sign permission parameters are valid
func (p *SignPermission) Check() error {
	if err := p.ID.Check(); err != nil {
		return trace.Wrap(err)
	}
	if p.SignID != nil {
		if err := p.SignID.Check(); err != nil {
			return trace.BadParameter("missing parameter IDs")
		}
	}
	return nil
}

// Collections manages stored collections - Workloads, Permissions, Authorities and TrustedRoots
type Collections interface {
	Permissions
	TrustedRoots
	Authorities
	Workloads
}
