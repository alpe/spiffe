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
	"crypto/x509/pkix"
	"sync"
	"sync/atomic"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/toolbox"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

// New returns new instance of Renewer service
func New(cfg Config) (*Service, error) {
	if err := cfg.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &Service{
		bundles: make(map[string]*bundleRenewer),
		certs:   make(map[string]*certRenewer),
	}, nil
}

// Config is a local service config
type Config struct {
	// Workload is a workload service, most likely grpc client
	Workload workload.Service
	// Storage is a storage implementation
	Storage Renewer
}

func (c *Config) Check() error {
	if c.Workload == nil {
		return trace.BadParameter("missing parameter Workload")
	}
	if c.Storage == nil {
		return trace.BadParameter("missing parameter Storage")
	}
	return nil
}

// Service is a local renewer service
type Service struct {
	Config
	sync.Mutex
	closed  uint32
	bundles map[string]*bundleRenewer
	certs   map[string]*certRenewer
}

// Load recovers service from stored state
func (s *Service) Load(ctx context.Context) error {
	certs, err := s.Storage.GetCertRequests(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	bundles, err := s.Storage.GetBundleRequests(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	for _, req := range bundles {
		if err := s.CreateBundleRequest(ctx, req); err != nil {
			return trace.Wrap(err)
		}
	}

	for _, req := range certs {
		if err := s.CreateCertRequest(ctx, req); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (s *Service) Close() error {
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return nil
	}

	s.Lock()
	defer s.Unlock()

	for _, b := range s.bundles {
		b.cancel()
	}

	s.bundles = nil

	for _, c := range s.certs {
		c.cancel()
	}
	s.certs = nil
	return s.Storage.Close()
}

func (s *Service) deleteBundleRequest(ctx context.Context, id string) error {
	s.Lock()
	defer s.Unlock()

	r, ok := s.bundles[id]
	if !ok {
		return trace.NotFound("bundle request %v not found", id)
	}

	r.cancel()
	delete(s.bundles, id)
	return nil
}

func (s *Service) createBundleRequest(ctx context.Context, req BundleRequest) error {
	s.Lock()
	defer s.Unlock()
	id := req.LocalID()

	if _, ok := s.bundles[id]; ok {
		return trace.AlreadyExists("bundle request %v already exists", id)
	}

	renewerContext, cancel := context.WithCancel(ctx)
	writeBundle := func(ctx context.Context, auths workload.Authorities, bundle *workload.TrustedRootBundle) error {
		if err := toolbox.RemoveAllInDir(req.TargetDir); err != nil {
			return trace.Wrap(err)
		}
		err := workload.WriteBundleToDirectory(ctx, req.TargetDir, auths, bundle)
		if err != nil {
			return trace.Wrap(err)
		}
		return nil
	}

	renewer, err := workload.NewBundleRenewer(workload.BundleRenewerConfig{
		Entry:               log.WithFields(log.Fields{trace.Component: constants.ComponentSPIFFE}),
		TrustedRootBundleID: req.BundleID,
		Service:             s.Workload,
		WriteBundle:         writeBundle,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	go func() {
		if err := renewer.Start(renewerContext); err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()

	s.bundles[id] = &bundleRenewer{
		request: req,
		cancel:  cancel,
		renewer: renewer,
	}
	return nil
}

func (s *Service) deleteCertRequest(ctx context.Context, id string) error {
	s.Lock()
	defer s.Unlock()

	r, ok := s.certs[id]
	if !ok {
		return trace.NotFound("cert request %v not found", id)
	}

	r.cancel()
	delete(s.certs, id)
	return nil
}

func (s *Service) createCertRequest(ctx context.Context, req CertRequest) error {
	s.Lock()
	defer s.Unlock()
	id := req.LocalID()

	if _, ok := s.certs[id]; ok {
		return trace.AlreadyExists("bundle request %v already exists", id)
	}

	renewerContext, cancel := context.WithCancel(ctx)

	rw, err := NewCertReadWriter(CertReadWriterConfig{
		KeyPath:  req.KeyPath,
		CertPath: req.CertPath,
		CAPath:   req.CAPath,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	renewer, err := workload.NewCertRenewer(workload.CertRenewerConfig{
		Entry: log.WithFields(log.Fields{
			trace.Component: constants.ComponentCLI,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: req.CertAuthorityID,
			ID:              req.ID,
			Subject: pkix.Name{
				CommonName: req.CommonName,
			},
			TTL: req.TTL,
		},
		ReadKeyPair:  rw.ReadKeyPair,
		WriteKeyPair: rw.WriteKeyPair,
		Service:      s.Workload,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	go func() {
		if err := renewer.Start(renewerContext); err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()

	s.certs[id] = &certRenewer{
		request: req,
		cancel:  cancel,
		renewer: renewer,
	}
	return nil
}

// CreateBundleRequest creates request to renew certficate bundles in local directory
func (s *Service) CreateBundleRequest(ctx context.Context, r BundleRequest) error {
	if err := r.Check(); err != nil {
		return trace.Wrap(err)
	}
	if err := s.createBundleRequest(ctx, r); err != nil {
		return trace.Wrap(err)
	}
	if err := s.Storage.CreateBundleRequest(ctx, r); err != nil {
		s.deleteBundleRequest(ctx, r.LocalID())
		return trace.Wrap(err)
	}
	return nil
}

// CreateCertRequest creates request to sign renew certificates in local directory
func (s *Service) CreateCertRequest(ctx context.Context, r CertRequest) error {
	if err := r.Check(); err != nil {
		return trace.Wrap(err)
	}
	if err := r.Check(); err != nil {
		return trace.Wrap(err)
	}
	if err := s.createCertRequest(ctx, r); err != nil {
		return trace.Wrap(err)
	}
	if err := s.Storage.CreateCertRequest(ctx, r); err != nil {
		s.deleteCertRequest(ctx, r.LocalID())
		return trace.Wrap(err)
	}
	return nil
}

// DeleteBundleRequest deletes BundleRequest
func (s *Service) DeleteBundleRequest(ctx context.Context, targetDir string) error {
	if targetDir == "" {
		return trace.BadParameter("missing parameter targetDir")
	}
	if err := s.deleteBundleRequest(ctx, LocalBundleRequestID(targetDir)); err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(s.Storage.DeleteBundleRequest(ctx, targetDir))
}

// DeleteCertRequest deletes certificate renewal request
func (s *Service) DeleteCertRequest(ctx context.Context, certPath string) error {
	if certPath == "" {
		return trace.BadParameter("missing parameter certPath")
	}
	if err := s.deleteCertRequest(ctx, LocalCertRequestID(certPath)); err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(s.Storage.DeleteCertRequest(ctx, certPath))
}

// GetCertRequests returns a list of cert requests
func (s *Service) GetCertRequests(ctx context.Context) ([]CertRequest, error) {
	return s.Storage.GetCertRequests(ctx)
}

// GetBundleRequests returns a list of bundle requests
func (s *Service) GetBundleRequests(ctx context.Context) ([]BundleRequest, error) {
	return s.Storage.GetBundleRequests(ctx)
}

type bundleRenewer struct {
	cancel  context.CancelFunc
	renewer *workload.BundleRenewer
	request BundleRequest
}

type certRenewer struct {
	cancel  context.CancelFunc
	renewer *workload.CertRenewer
	request CertRequest
}
