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
	"net"
	"net/http"
	_ "net/http/pprof"
	"path/filepath"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/k8s"
	"github.com/spiffe/spiffe/lib/toolbox"
	"github.com/spiffe/spiffe/lib/workload"
	"github.com/spiffe/spiffe/lib/workload/api"
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

func (p *Process) startNewServer(ctx context.Context, listener net.Listener, keyPair *workload.KeyPair) error {
	ca, err := p.localService.GetCertAuthority(ctx, constants.AdminOrg)
	if err != nil {
		return trace.Wrap(err)
	}

	// creates new API authenticator using client certificates
	auth, err := api.NewAuthenticator(p.backend)
	if err != nil {
		return trace.Wrap(err)
	}

	// creates new server implemenation with Etcd-backed ACL
	server, err := api.NewServer(workload.NewACL(p.backend, auth, clockwork.NewRealClock()))
	if err != nil {
		return trace.Wrap(err)
	}

	// spins up new GRPC server
	grpcServer, err := api.NewServerFromConfig(api.ServerConfig{
		TLSKey:  keyPair.KeyPEM,
		TLSCert: keyPair.CertPEM,
		TLSCA:   ca.Cert,
		Server:  server,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	go func() {
		err := trace.Wrap(grpcServer.Serve(listener))
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()
	return nil
}

func (p *Process) restartServer(ctx context.Context, listener net.Listener, keyPair *workload.KeyPair) (net.Listener, error) {
	var err error
	restartFn := func() (net.Listener, error) {
		// start new server
		listener, err := net.Listen("tcp", p.RPCListenAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		p.Infof("GRPC server is listening on %v", p.RPCListenAddr)
		if err := p.startNewServer(ctx, listener, keyPair); err != nil {
			return nil, trace.Wrap(err)
		}
		return listener, nil
	}
	if listener != nil {
		// close the previous listener to stop the previous server
		if err = listener.Close(); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// This loop is subtle.  It will try restarting the server until there is no
	// error.  This can happen if someone else is listening on that address or the
	// previous server is taking its time shutting down.
	listener, err = restartFn()
	if err == nil {
		return listener, nil
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.Debugf("context is closing, returning")
			return nil, trace.ConnectionProblem(nil, "server is shutting dow")
		case <-ticker.C:
			listener, err := restartFn()
			if err == nil {
				return listener, nil
			}
		}
	}
}

func (p *Process) listenAndServe(ctx context.Context) error {
	// keep in memory credentials for server
	mem := workload.NewMemStorage()
	eventsC := make(chan *workload.KeyPair, 1)

	renewer, err := workload.NewCertRenewer(workload.CertRenewerConfig{
		Clock: clockwork.NewRealClock(),
		Entry: log.WithFields(log.Fields{
			trace.Component: constants.ComponentSPIFFE,
			"id":            p.ServerID,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: constants.AdminOrg,
			ID:              identity.MustParseID(p.ServerID),
			Subject: pkix.Name{
				CommonName: p.AdvertiseHostname,
			},
			TTL: constants.DefaultLocalCertTTL,
		},
		ReadKeyPair: func() (*workload.KeyPair, error) {
			keyPEM, err := mem.ReadPath("key")
			if err != nil {
				return nil, trace.Wrap(err)
			}
			certPEM, err := mem.ReadPath("cert")
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return &workload.KeyPair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
		},
		WriteKeyPair: func(keyPair workload.KeyPair) error {
			if err := mem.WritePath("key", keyPair.KeyPEM); err != nil {
				return trace.Wrap(err)
			}
			if err := mem.WritePath("cert", keyPair.CertPEM); err != nil {
				return trace.Wrap(err)
			}
			return nil
		},
		Service: p.localService,
		EventsC: eventsC,
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

	var listener net.Listener
	for {
		select {
		case <-ctx.Done():
			p.Debugf("context is closing")
			if listener != nil {
				// close the previous listener to stop the previous server
				if err = listener.Close(); err != nil {
					return trace.Wrap(err)
				}
			}
			return nil
		case keyPair := <-eventsC:
			listener, err = p.restartServer(ctx, listener, keyPair)
			if err != nil {
				return trace.Wrap(err)
			}
		}
	}
}

// initLocalAdminCreds starts new renewer process that will create and rotate certs
// for local admins
func (p *Process) initLocalAdminCreds(ctx context.Context) error {
	keyPath := filepath.Join(p.StateDir, constants.AdminKeyFilename)
	certPath := filepath.Join(p.StateDir, constants.AdminCertFilename)
	renewer, err := workload.NewCertRenewer(workload.CertRenewerConfig{
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
		ReadKeyPair: func() (*workload.KeyPair, error) {
			keyPEM, err := toolbox.ReadPath(keyPath)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			certPEM, err := toolbox.ReadPath(certPath)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return &workload.KeyPair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
		},
		WriteKeyPair: func(keyPair workload.KeyPair) error {
			if err := toolbox.WritePath(keyPath, keyPair.KeyPEM, constants.DefaultPrivateFileMask); err != nil {
				return trace.Wrap(err)
			}
			if err := toolbox.WritePath(certPath, keyPair.CertPEM, constants.DefaultPrivateFileMask); err != nil {
				return trace.Wrap(err)
			}
			return nil
		},
		Service: p.localService,
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

	return workload.SetAdminPermissions(ctx, p.localService, p.adminID, constants.DefaultCATTL)
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
		p.Infof("setting up Admin cert authority")
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
		if ca, err = p.localService.GetCertAuthority(ctx, constants.AdminOrg); err != nil {
			return trace.Wrap(err)
		}
	}
	caPath := filepath.Join(p.StateDir, constants.AdminCertCAFilename)
	return toolbox.WritePath(caPath, ca.Cert, constants.DefaultPrivateFileMask)
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
	if p.K8s.Enabled {
		p.Infof("starting K8s helper goroutine")
		service, err := k8s.NewService(k8s.ServiceConfig{
			Service: p.localService,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		go service.Serve(ctx)
	} else {
		p.Infof("not starting K8s helper goroutine")
	}

	if err := p.listenAndServe(ctx); err != nil {
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
