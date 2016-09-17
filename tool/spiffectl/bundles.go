package main

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/toolbox"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

func bundleCreate(ctx context.Context, service workload.Service, id string, directories []string, certAuthorityIDs []string, replace bool) error {
	if len(directories) == 0 && len(certAuthorityIDs) == 0 {
		return trace.BadParameter("please provide directory or cert authority ids")
	}
	bundle := workload.TrustedRootBundle{
		ID: id,
	}
	for _, id := range certAuthorityIDs {
		_, err := service.GetCertAuthorityCert(ctx, id)
		if err != nil {
			return trace.BadParameter("certificate authority %v does not exist", id)
		}
	}
	bundle.CertAuthorityIDs = certAuthorityIDs
	for _, directory := range directories {
		fmt.Printf("reading the contents of %v\n", directory)
		files, err := ioutil.ReadDir(directory)
		if err != nil {
			return trace.Wrap(err, "failed to read contents of %v", directory)
		}
		for _, f := range files {
			if f.IsDir() {
				fmt.Printf("skipping directory %v\n", directory)
				continue
			}
			data, err := toolbox.ReadPath(filepath.Join(directory, f.Name()))
			if err != nil {
				fmt.Printf("skipping file %v, err: %v\n", f.Name(), err)
				continue
			}
			_, err = workload.ParseCertificatePEM(data)
			if err != nil {
				fmt.Printf("skipping file %v, err: %v\n", f.Name(), err)
				continue
			}

			bundle.Certs = append(bundle.Certs, workload.TrustedRootCert{
				ID:       f.Name(),
				Filename: f.Name(),
				Cert:     data,
			})
		}
		fmt.Printf("imported %v from %v\n", len(bundle.Certs), directory)
	}

	if replace {
		err := service.UpsertTrustedRootBundle(ctx, bundle)
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("bundle %v successfully updated\n", bundle.ID)
		return nil
	}
	err := service.CreateTrustedRootBundle(ctx, bundle)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("bundle %v successfully created\n", bundle.ID)
	return nil
}

func execHook(cmd string) {
	args := strings.Split(cmd, " ")
	out, err := exec.Command(args[0], args[1:]...).Output()
	fmt.Printf("hook(%v): %v\n", cmd, string(out))
	if err != nil {
		log.Error(trace.DebugReport(err))
	}
}

func bundleExport(ctx context.Context, service workload.Service, bundleID string, targetDir string, watchUpdates bool, hooks []string) error {
	if _, err := toolbox.StatDir(targetDir); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		err = toolbox.Mkdir(targetDir, constants.DefaultPrivateDirMask)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	writeBundle := func(ctx context.Context, auths workload.Authorities, bundle *workload.TrustedRootBundle) error {
		if err := toolbox.RemoveAllInDir(targetDir); err != nil {
			return trace.Wrap(err)
		}
		err := workload.WriteBundleToDirectory(ctx, targetDir, service, bundle)
		if err != nil {
			return trace.Wrap(err)
		}
		return nil
	}
	if !watchUpdates {
		bundle, err := service.GetTrustedRootBundle(ctx, bundleID)
		if err != nil {
			return trace.Wrap(err)
		}
		if err := writeBundle(ctx, service, bundle); err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("%v successfully exported\n", bundleToString(bundle))
		if len(hooks) != 0 {
			for _, h := range hooks {
				execHook(h)
			}
		}
		return nil
	}
	eventsC := make(chan *workload.TrustedRootBundle, 10)
	r, err := workload.NewBundleRenewer(workload.BundleRenewerConfig{
		Entry:               log.WithFields(log.Fields{trace.Component: constants.ComponentCLI}),
		TrustedRootBundleID: bundleID,
		Service:             service,
		WriteBundle:         writeBundle,
		EventsC:             eventsC,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Debugf("context is closing, returning")
				return
			case bundle := <-eventsC:
				fmt.Printf("%v successfully exported\n", bundleToString(bundle))
				if len(hooks) != 0 {
					for _, h := range hooks {
						go execHook(h)
					}
				}
			}
		}
	}()

	go r.Start(ctx)
	<-ctx.Done()
	return nil
}

func bundlesList(ctx context.Context, service workload.Service) error {
	bundles, err := service.GetTrustedRootBundles(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	printHeader("Trusted CA root bundles")
	if len(bundles) == 0 {
		fmt.Printf("\nThere are no certificate root bundles available yet. Create one by using command 'spiffectl bundle create'\n")
	}
	for _, b := range bundles {
		fmt.Printf("* %v\n", bundleToString(&b))
	}
	fmt.Printf("\n")
	return nil
}

func bundleToString(b *workload.TrustedRootBundle) string {
	var cas string
	if len(b.CertAuthorityIDs) != 0 {
		cas = fmt.Sprintf(", certificate authorites: %v", strings.Join(b.CertAuthorityIDs, ","))
	}
	var certs string
	if len(b.Certs) != 0 {
		certs = fmt.Sprintf(", external certificates: %v", len(b.Certs))
	}
	return fmt.Sprintf("id: '%v'%v%v", b.ID, cas, certs)
}
