package process

import (
	"crypto/x509/pkix"
	"net/http"
	_ "net/http/pprof"
	"path/filepath"

	"github.com/spiffe/spiffe"
	"github.com/spiffe/spiffe/workload"
	"github.com/spiffe/spiffe/workload/storage/etcdv2"

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
		spiffe.InitLoggerDebug()
	} else {
		spiffe.InitLoggerCLI()
	}
	return &Process{
		Config:  config,
		Entry:   log.WithFields(log.Fields{trace.Component: spiffe.ComponentSPIFFE}),
		adminID: spiffe.MustParseID(spiffe.AdminID),
	}, nil
}

type Process struct {
	Config
	*log.Entry
	backend      *etcdv2.Backend
	localService workload.Service
	adminID      spiffe.ID
}

func (p *Process) initLocalAdminCreds(ctx context.Context) error {
	keyPath := filepath.Join(p.StateDir, "admin.pem")
	certPath := filepath.Join(p.StateDir, "admin.cert")
	// start new renewer process
	renewer, err := workload.NewRenewer(workload.RenewerConfig{
		Clock: clockwork.NewRealClock(),
		Entry: log.WithFields(log.Fields{
			trace.Component: spiffe.ComponentSPIFFE,
			"id":            p.adminID,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: spiffe.AdminOrg,
			ID:              p.adminID,
			Subject: pkix.Name{
				CommonName: p.AdvertiseHostname,
			},
			TTL: spiffe.DefaultLocalCertTTL,
		},
		ReadKey: func() ([]byte, error) {
			return ReadPath(keyPath)
		},
		ReadCert: func() ([]byte, error) {
			return ReadPath(certPath)
		},
		WriteKey: func(data []byte) error {
			return WritePath(keyPath, data, spiffe.DefaultPrivateFileMask)
		},
		WriteCert: func(data []byte) error {
			return WritePath(certPath, data, spiffe.DefaultPrivateFileMask)
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
	_, err := p.localService.GetCertAuthority(ctx, spiffe.AdminOrg)
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		log.Infof("setting up Admin cert authority")
		keyPEM, certPEM, err := spiffe.GenerateSelfSignedCA(pkix.Name{
			CommonName:   spiffe.AdminOrg,
			Organization: []string{spiffe.AdminOrg},
		}, nil, spiffe.DefaultCATTL)
		err = p.localService.CreateCertAuthority(ctx, workload.CertAuthority{
			ID:         spiffe.AdminOrg,
			Cert:       certPEM,
			PrivateKey: keyPEM,
		})
		if err != nil {
			if !trace.IsAlreadyExists(err) {
				return trace.Wrap(err)
			}
		}
		if _, err = p.localService.GetCertAuthority(ctx, spiffe.AdminOrg); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
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
