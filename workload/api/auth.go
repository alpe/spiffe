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

package api

import (
	"github.com/spiffe/spiffe"
	"github.com/spiffe/spiffe/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// NewAuthenticator returns new authentticator based on TLS authentication information
// and SPIFFE ID that should be provided in the certificate
func NewAuthenticator(ctx context.Context, permissions workload.PermissionsReader) (*Authenticator, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, trace.AccessDenied("missing authentication")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, trace.AccessDenied("unsupported authentication type")
	}
	if len(info.State.PeerCertificates) != 1 {
		log.Errorf("unsupported peer certs amount: %#v", info.State.PeerCertificates)
		return nil, trace.AccessDenied("unsupported autnentication type")
	}

	ids, err := spiffe.IDsFromCertificate(info.State.PeerCertificates[0])
	if err != nil {
		log.Errorf("error parsing: %#v", trace.DebugReport(err))
		return nil, trace.AccessDenied("missing SPIFFE id")
	}

	if len(ids) == 0 {
		return nil, trace.AccessDenied("missing SPIFFE id")
	}

	if len(ids) > 1 {
		return nil, trace.AccessDenied("multiple SPIFFE ids found")
	}

	return &Authenticator{
		ID: ids[0],
		P:  permissions,
	}, nil
}

type Authenticator struct {
	P  workload.PermissionsReader
	ID spiffe.ID
}

// GetSignPermission return permission for actor identified by SPIFFE ID
func (a *Authenticator) GetSignPermission(ctx context.Context, sp workload.SignPermission) (*workload.SignPermission, error) {
	sp.ID = a.ID
	out, err := a.P.GetSignPermission(ctx, sp)
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.AccessDenied(sp.String())
		}
		return nil, trace.Wrap(err)
	}
	return out, nil
}

// GetPermission returns permission for actor identified by SPIFFE ID
func (a *Authenticator) GetPermission(ctx context.Context, p workload.Permission) (*workload.Permission, error) {
	p.ID = a.ID
	out, err := a.P.GetPermission(ctx, p)
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.AccessDenied(p.String())
		}
		return nil, trace.Wrap(err)
	}
	return out, nil
}
