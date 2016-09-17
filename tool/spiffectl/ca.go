package main

import (
	"fmt"

	"github.com/spiffe/spiffe/lib/workload"

	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

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
