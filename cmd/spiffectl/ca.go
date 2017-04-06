package main

import (
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/local"
	"github.com/spiffe/spiffe/lib/toolbox"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"

	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

func certAuthoritySign(ctx context.Context, service workload.Service, id identity.ID, certAuthorityID, keyPath, certPath, caPath, commonName string, ttl time.Duration, watchUpdates bool, hooks []string) error {
	eventsC := make(chan *workload.KeyPair, 10)
	rw, err := local.NewCertReadWriter(local.CertReadWriterConfig{
		KeyPath:  keyPath,
		CertPath: certPath,
		CAPath:   caPath,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	renewer, err := workload.NewCertRenewer(workload.CertRenewerConfig{
		Entry: log.WithFields(log.Fields{
			trace.Component: constants.ComponentCLI,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: certAuthorityID,
			ID:              id,
			Subject: pkix.Name{
				CommonName: commonName,
			},
			TTL: ttl,
		},
		ReadKeyPair:  rw.ReadKeyPair,
		WriteKeyPair: rw.WriteKeyPair,
		Service:      service,
		EventsC:      eventsC,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if !watchUpdates {
		err := renewer.Renew(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("%v successfully generated\n", commonName)
		if len(hooks) != 0 {
			for _, h := range hooks {
				execHook(h)
			}
		}
		return nil
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Debugf("context is closing, returning")
				return
			case <-eventsC:
				fmt.Printf("%v successfully renewed\n", commonName)
				if len(hooks) != 0 {
					for _, h := range hooks {
						go execHook(h)
					}
				}
			}
		}
	}()

	go renewer.Start(ctx)
	<-ctx.Done()
	return nil
}

func certAuthorityDelete(ctx context.Context, service workload.Service, id string) error {
	err := service.DeleteCertAuthority(ctx, id)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("cert authority %v successfully deleted\n", id)
	return nil
}

func certAuthorityGenerate(ctx context.Context, service workload.Service, id, commonName, org string, ttl time.Duration, replace bool) error {
	keyPEM, certPEM, err := identity.GenerateSelfSignedCA(pkix.Name{
		CommonName:   commonName,
		Organization: []string{org},
	}, nil, ttl)
	if err != nil {
		return trace.Wrap(err)
	}
	certAuthority := workload.CertAuthority{ID: id, PrivateKey: keyPEM, Cert: certPEM}
	if replace {
		if err := service.UpsertCertAuthority(ctx, certAuthority); err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("%v successfully updated\n", certAuthorityToString(certAuthority))
		return nil
	}
	if err := service.CreateCertAuthority(ctx, certAuthority); err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("%v successfully created\n", certAuthorityToString(certAuthority))
	return nil
}

func certAuthorityImport(ctx context.Context, service workload.Service, id, keyPath, certPath string, replace bool) error {
	keyPEM, err := toolbox.ReadPath(keyPath)
	if err != nil {
		return trace.Wrap(err)
	}
	certPEM, err := toolbox.ReadPath(certPath)
	if err != nil {
		return trace.Wrap(err)
	}
	certAuthority := workload.CertAuthority{ID: id, PrivateKey: keyPEM, Cert: certPEM}
	if err := certAuthority.Check(); err != nil {
		return trace.Wrap(err)
	}
	if replace {
		if err := service.UpsertCertAuthority(ctx, certAuthority); err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("%v successfully updated\n", certAuthorityToString(certAuthority))
		return nil
	}
	if err := service.UpsertCertAuthority(ctx, certAuthority); err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("%v successfully created\n", certAuthorityToString(certAuthority))
	return nil
}

func certAuthoritiesList(ctx context.Context, service workload.Service) error {
	cas, err := service.GetCertAuthoritiesCerts(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	printHeader("Certificate Authorities")
	if len(cas) == 0 {
		fmt.Printf("\nThere are no certificate authorities yet. Create one by using command 'spiffectl ca create'\n")
	}
	for _, ca := range cas {
		fmt.Printf("* %v\n", certAuthorityToString(ca))
	}
	fmt.Printf("\n")
	return nil
}

func certAuthorityToString(ca workload.CertAuthority) string {
	var certInfo string
	cert, err := workload.ParseCertificatePEM(ca.Cert)
	if err != nil {
		certInfo = fmt.Sprintf("<parse error: %v>", trace.UserMessage(err))
	} else {
		certInfo = fmt.Sprintf(", CN=%v, expires: %v", cert.Subject.CommonName, cert.NotAfter)
	}
	return fmt.Sprintf("id: '%v'%v", ca.ID, certInfo)
}
