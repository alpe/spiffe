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
	"github.com/spiffe/spiffe/workload"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func NewClient(client ServiceClient) (*Client, error) {
	if client == nil {
		return nil, trace.BadParameter("missing parameter service")
	}
	return &Client{Client: client}, nil
}

// Client is GRPC based Workload service client
type Client struct {
	Client ServiceClient
}

// ProcessCertificateRequest process x509 CSR to sign with particular TTL and specifies which CertificateAuthority to usePro
func (s *Client) ProcessCertificateRequest(ctx context.Context, req *workload.CertificateRequest) (*workload.CertificateResponse, error) {
	var header metadata.MD
	re, err := s.Client.ProcessCertificateRequest(ctx, &CertificateRequest{
		CertAuthorityID: req.CertAuthorityID,
		TTL:             int64(req.TTL),
		CSR:             req.CSR,
	}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return &workload.CertificateResponse{
		Cert: re.Cert,
	}, nil
}
