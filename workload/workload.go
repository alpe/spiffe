/*
Copyright 2016 SPIFFE authors

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
	"golang.org/x/net/context"
)

type CertAuthority struct {
	// ID is a unique identifier of the authority, usually SPIFFE org name
	ID string
	// Cert is a certificate of the certificate signing authority
	Cert x509.Certificate
	// PrivateKey is optional (in case if this CA can sign, otherwise it can
	// be used as a trusted root
	PrivateKey crypto.Signer
}

// Authorities manages certificate authorities
type Authorities interface {
	// UpsertCertAuthority updates or inserts certificate authority
	// In case if CA can sign, Private
	UpsertCertAuthority(CertAuthority) error
	// GetCertAuthority returns Certificate Authority by given ID
	GetCertAuthority(id string) (*CertAuthority, error)
	// DeleteCertAuthority deletes Certificate Authority by ID
	DeleteCertAuthority(id string) error
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
	UpsertWorkload(ctx context.Context, w Workload) (*Workload, error)
	// DeleteWorkload deletes workload
	DeleteWorkload(ctx context.Context, ID string) error
	// GetWorkload returns workload identified by ID
	GetWorkload(ctx context.Context, ID string) (*Workload, error)
	// Subscribe returns a stream of events associated with given workload IDs
	// if you wish to cancel the stream, use ctx.Close
	Subscribe(ctx context.Context, IDs []string) (<-chan WorkloadEvent, error)
}

// Signer is a workload-aware certificate signer.
// For example to generate CSR for SPIFFE ID 'urn:spiffe:example.com:opaque:id'
// and workload 'dev', NodeCA will produce CSR with the following fields set:
//   * SubjectCommonName: example.com
//   * SubjectAltName: urn:spiffe:example.com:opaque.id
//   * Extension: spiffe ASN, value: workload ID
//
// Workload Server will:
//
// * Make sure that workload 'dev' has assigned SPIFFE id `urn:spiffe:example.com:opaque.id`
// * Fetch CertAuthority with ID `example.com`
// * Use it to process CSR with TTL <= MaxTTL in the ScopedID of the workload
type Signer interface {
	ProcessCSR(x509.CertificateRequest) (x509.Certificate, error)
}
