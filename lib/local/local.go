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

// package local implements utilities for local filesystem certs
package local

import (
	"io"
	"time"

	"github.com/spiffe/spiffe/lib/identity"

	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

// Renewer renews bundles and certificates on a file system
type Renewer interface {
	// CreateBundleRequest creates request to renew certficate bundles in local directory
	CreateBundleRequest(ctx context.Context, r BundleRequest) error
	// CreateCertRequest creates request to sign renew certificates in local directory
	CreateCertRequest(ctx context.Context, r CertRequest) error
	// DeleteBundleRequest deletes BundleRequest
	DeleteBundleRequest(ctx context.Context, id string) error
	// DeleteCertRequest deletes certificate renewal request
	DeleteCertRequest(ctx context.Context, id string) error
	// GetCertRequests returns a list of cert requests
	GetCertRequests(ctx context.Context) ([]CertRequest, error)
	// GetBundleRequests returns a list of bundle requests
	GetBundleRequests(ctx context.Context) ([]BundleRequest, error)
	// Closer is to close all local resources
	io.Closer
}

// BundleRequest requests to export bundle ID to particular directory
type BundleRequest struct {
	// ID is a unique request ID
	ID string `json:"id" yaml:"id"`
	// BundleID is a certificate bundle ID
	BundleID string `json:"bundleID" yaml:"bundleID"`
	// TargetDir is a target directory where to put the bundle contents
	TargetDir string `json:"targetDir" yaml:"targetDir"`
}

func (b *BundleRequest) Check() error {
	if b.ID == "" {
		return trace.BadParameter("no request ID specified")
	}
	if b.BundleID == "" {
		return trace.BadParameter("no bundle ID specified")
	}
	if b.TargetDir == "" {
		return trace.BadParameter("missing target directory")
	}
	return nil
}

// CertRequest is a request to get a private key and certificate signed by cert authority
type CertRequest struct {
	// ID is a unique request ID
	ID string `json:"id"`
	// CertAuthorityID is ID of the certificate authority
	CertAuthorityID string `json:"certAuthorityID" yaml:"certAuthorityID"`
	// Identity is identity to generate
	Identity identity.ID `json:"identity" yaml:"identity"`
	// CommonName is a common name to produce
	CommonName string `json:"commonName" yaml:"commonName"`
	// TTL is certificate TTLxo
	TTL time.Duration `json:"ttl" yaml:"ttl"`
	// KeyPath is a key path of the certificate
	KeyPath string `json:"keyPath" yaml:"keyPath"`
	// CertPath is a path of the generated certificate
	CertPath string `json:"certPath" yaml:"certPath"`
	// CAPath is a path of the certificate authority cert  that signed this cert
	CAPath string `json:"caPath" yaml:"caPath"`
}

func (s *CertRequest) Check() error {
	if s.ID == "" {
		return trace.BadParameter("no request ID specified")
	}
	if s.CertAuthorityID == "" {
		return trace.BadParameter("missing parameter cert authoirity ID")
	}
	if err := s.Identity.Check(); err != nil {
		return trace.Wrap(err)
	}
	if s.CommonName == "" {
		return trace.BadParameter("missing parameter commonName")
	}
	if s.TTL == 0 {
		return trace.BadParameter("missing parameter TTL")
	}
	if s.KeyPath == "" {
		return trace.BadParameter("missing parameter KeyPath")
	}
	if s.CertPath == "" {
		return trace.BadParameter("missing parameter CertPath")
	}
	return nil
}
