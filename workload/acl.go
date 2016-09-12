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

package workload

import (
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

// ACL implements workload interfaces and applies permission checking for them
type ACL struct {
	Auth    Permissions
	Service Service
}

func (a *ACL) ProcessCertificateRequest(ctx context.Context, req CertificateRequest) (*CertificateResponse, error) {
	if err := req.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	csr, err := ParseCertificateRequestPEM(req.CSR)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	permission, err := a.Auth.GetSignPermission(ctx, SignPermission{
		CertAuthorityID: req.CertAuthorityID,
		Org:             csr.Subject.CommonName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if permission.MaxTTL < req.TTL {
		return nil, trace.BadParameter("%v exceeds allowed value of %v", req.TTL, permission.MaxTTL)
	}

	return a.Service.ProcessCertificateRequest(ctx, req)
}
