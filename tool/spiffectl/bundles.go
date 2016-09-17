package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/process"
	"github.com/spiffe/spiffe/lib/workload"

	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

func bundleCreate(ctx context.Context, service workload.Service, replace bool, id string, directories []string, certAuthorityIDs []string) error {
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
			data, err := process.ReadPath(filepath.Join(directory, f.Name()))
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
	}
	err := service.CreateTrustedRootBundle(ctx, bundle)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("bundle %v successfully created\n", bundle.ID)
	return nil
}

func bundleExport(ctx context.Context, service workload.Service, targetDirectory string, watchUpdates bool) error {
	if _, err := process.StatDir(targetDirectory); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		err = os.Mkdir(targetDirectory, constants.DefaultPrivateDirMask)
		if err != nil {
			return trace.ConvertSystemError(err)
		}
	}
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
		fmt.Printf("* %v\n", bundleToString(b))
	}
	fmt.Printf("\n")
	return nil
}

func bundleToString(b workload.TrustedRootBundle) string {
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
