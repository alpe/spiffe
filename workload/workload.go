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
	// ID is a unique identifier of the authority
	ID string
	// Cert is a certificate of the certificate signing authority
	Cert x509.Certificate
	// PrivateKey is optional (in case if this CA can sign)
	PrivateKey crypto.Signer
}

// Authorities manages certificate authorities
type Authorities interface {
	UpsertCertAuthority(CertAuthority) error
	GetCertAuthority(id string) (CertAuthority, error)
	DeleteCertAuthority(id string)
}

// ScopedID represents SPIFFE ID with attached
// scope of usage (limits Max TTL for certificate issued)
type ScopedID struct {
	ID        spiffe.ID
	MaxTTL    time.Duration
	IsDefault bool
}

type Workload struct {
	ID             string
	Identities     []ScopedID
	TrustedRootIDs []string
}

type WorkloadEvent struct {
	ID       string
	Type     string
	Workload Workload
}

const (
	EventWorkloadUpdated = "WorkloadUpdated"
	EventWorkloadDeleted = "WorkloadDeleted"
)

// Workloads is a SPIFFE workload API
type Workloads interface {
	UpsertWorkload(Workload) (*Workload, error)
	DeleteWorkload(ID string) error
	GetWorkload(ID string) (*Workload, error)
	Subscribe(ctx context.Context, IDs []string) (<-chan WorkloadEvent, error)
}

// Signer is workload signer
type Signer interface {
	ProcessCSR(x509.CertificateRequest) (x509.Certificate, error)
}
