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

package process

import (
	"crypto/x509/pkix"
	"net/http"
	_ "net/http/pprof"
	"path/filepath"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/workload"
	"github.com/spiffe/spiffe/lib/workload/storage/etcdv2"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
)

func New(config Config) (*Process, error) {
	if err := config.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	if config.Debug {
		identity.InitLoggerDebug()
	} else {
		identity.InitLoggerCLI()
	}
	return &Process{
		Config:  config,
		Entry:   log.WithFields(log.Fields{trace.Component: constants.ComponentSPIFFE}),
		adminID: identity.MustParseID(constants.AdminID),
	}, nil
}

type Process struct {
	Config
	*log.Entry
	backend      *etcdv2.Backend
	localService workload.Service
	adminID      identity.ID
}

func (p *Process) initLocalAdminCreds(ctx context.Context) error {
	keyPath := filepath.Join(p.StateDir, constants.AdminKeyFilename)
	certPath := filepath.Join(p.StateDir, constants.AdminCertFilename)
	// start new renewer process
	renewer, err := workload.NewRenewer(workload.RenewerConfig{
		Clock: clockwork.NewRealClock(),
		Entry: log.WithFields(log.Fields{
			trace.Component: constants.ComponentSPIFFE,
			"id":            p.adminID,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: constants.AdminOrg,
			ID:              p.adminID,
			Subject: pkix.Name{
				CommonName: p.AdvertiseHostname,
			},
			TTL: constants.DefaultLocalCertTTL,
		},
		ReadKey: func() ([]byte, error) {
			return ReadPath(keyPath)
		},
		ReadCert: func() ([]byte, error) {
			return ReadPath(certPath)
		},
		WriteKey: func(data []byte) error {
			return WritePath(keyPath, data, constants.DefaultPrivateFileMask)
		},
		WriteCert: func(data []byte) error {
			return WritePath(certPath, data, constants.DefaultPrivateFileMask)
		},
		Signer: p.localService,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	go func() {
		err := renewer.Start(ctx)
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()
	return nil
}

// initLocalService initialises local SPIFFE service using ETCD backend
func (p *Process) initLocalService(ctx context.Context) error {
	p.localService = workload.NewService(p.backend, nil)

	// init local certificate authority used for node communications
	ca, err := p.localService.GetCertAuthority(ctx, constants.AdminOrg)
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		log.Infof("setting up Admin cert authority")
		keyPEM, certPEM, err := identity.GenerateSelfSignedCA(pkix.Name{
			CommonName:   constants.AdminOrg,
			Organization: []string{constants.AdminOrg},
		}, nil, constants.DefaultCATTL)
		err = p.localService.CreateCertAuthority(ctx, workload.CertAuthority{
			ID:         constants.AdminOrg,
			Cert:       certPEM,
			PrivateKey: keyPEM,
		})
		if err != nil {
			if !trace.IsAlreadyExists(err) {
				return trace.Wrap(err)
			}
		}
		if _, err = p.localService.GetCertAuthority(ctx, constants.AdminOrg); err != nil {
			return trace.Wrap(err)
		}
	}
	caPath := filepath.Join(p.StateDir, constants.AdminCertCAFilename)
	return WritePath(caPath, ca.Cert, constants.DefaultPrivateFileMask)
}

func (p *Process) startService(ctx context.Context) error {
	var err error
	p.backend, err = etcdv2.New(p.Config.Backend.EtcdV2)
	if err != nil {
		return trace.Wrap(err)
	}

	if err = p.initLocalService(ctx); err != nil {
		return trace.Wrap(err)
	}

	if err = p.initLocalAdminCreds(ctx); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (p *Process) Start(ctx context.Context) error {
	prettyConfig, _ := yaml.Marshal(p.Config)
	p.Infof("starting with config: %v", string(prettyConfig))

	if p.ProfileListenAddr != "" {
		p.Infof("starting HTTP profile endpoint on %v", p.ProfileListenAddr)
		go func() {
			err := http.ListenAndServe(p.ProfileListenAddr, nil)
			if err != nil {
				log.Error(trace.DebugReport(err))
			}
		}()
	}

	if err := p.startService(ctx); err != nil {
		return trace.Wrap(err)
	}

	select {
	case <-ctx.Done():
		p.Infof("context closed, exiting")
		return nil
	}
}
