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
	"time"

	"github.com/spiffe/spiffe/workload"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"golang.org/x/net/context"
)

func NewServer(service workload.Service) (*Server, error) {
	if service == nil {
		return nil, trace.BadParameter("missing parameter service")
	}
	return &Server{Service: service}, nil
}

// Server is used to implement gw.EchoServer
type Server struct {
	Service workload.Service
}

// Sign implements Signer
func (s *Server) ProcessCertificateRequest(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	re, err := s.Service.ProcessCertificateRequest(ctx, workload.CertificateRequest{
		CertAuthorityID: req.CertAuthorityID,
		TTL:             time.Duration(req.TTL),
		CSR:             req.CSR,
	})
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &CertificateResponse{
		Cert: re.Cert,
	}, nil
}
