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

package localapi

import (
	"time"

	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/local"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"golang.org/x/net/context"
)

func NewServer(service local.Renewer) (*Server, error) {
	if service == nil {
		return nil, trace.BadParameter("missing parameter service")
	}
	return &Server{Service: service}, nil
}

// Server is used to implement gw.EchoServer
type Server struct {
	Service local.Renewer
}

func (s *Server) CreateCertRequest(ctx context.Context, req *CertRequest) (*empty.Empty, error) {
	out, err := certRequestFromGRPC(req)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	err = s.Service.CreateCertRequest(ctx, *out)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetCertRequests(ctx context.Context, _ *empty.Empty) (*CertRequests, error) {
	reqs, err := s.Service.GetCertRequests(ctx)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &CertRequests{CertRequests: certRequestsToGRPC(reqs)}, nil
}

func (s *Server) DeleteCertRequest(ctx context.Context, id *ID) (*empty.Empty, error) {
	err := s.Service.DeleteCertRequest(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) CreateBundleRequest(ctx context.Context, req *BundleRequest) (*empty.Empty, error) {
	err := s.Service.CreateBundleRequest(ctx, *bundleRequestFromGRPC(req))
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetBundleRequests(ctx context.Context, _ *empty.Empty) (*BundleRequests, error) {
	reqs, err := s.Service.GetBundleRequests(ctx)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &BundleRequests{BundleRequests: bundleRequestsToGRPC(reqs)}, nil
}

func (s *Server) DeleteBundleRequest(ctx context.Context, id *ID) (*empty.Empty, error) {
	err := s.Service.DeleteBundleRequest(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func certRequestToGRPC(in local.CertRequest) *CertRequest {
	return &CertRequest{
		CertAuthorityID: in.CertAuthorityID,
		ID:              in.ID.String(),
		CommonName:      in.CommonName,
		TTL:             int64(in.TTL),
		KeyPath:         in.KeyPath,
		CertPath:        in.CertPath,
		CAPath:          in.CAPath,
	}
}

func certRequestFromGRPC(in *CertRequest) (*local.CertRequest, error) {
	id, err := identity.ParseID(in.ID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &local.CertRequest{
		CertAuthorityID: in.CertAuthorityID,
		ID:              *id,
		CommonName:      in.CommonName,
		TTL:             time.Duration(in.TTL),
		KeyPath:         in.KeyPath,
		CertPath:        in.CertPath,
		CAPath:          in.CAPath,
	}, nil
}

func certRequestsToGRPC(in []local.CertRequest) []*CertRequest {
	out := make([]*CertRequest, len(in))
	for i := range in {
		out[i] = certRequestToGRPC(in[i])
	}
	return out
}

func certRequestsFromGRPC(in []*CertRequest) ([]local.CertRequest, error) {
	out := make([]local.CertRequest, len(in))
	for i := range in {
		r, err := certRequestFromGRPC(in[i])
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out[i] = *r
	}
	return out, nil
}

func bundleRequestToGRPC(in local.BundleRequest) *BundleRequest {
	return &BundleRequest{
		BundleID:  in.BundleID,
		TargetDir: in.TargetDir,
	}
}

func bundleRequestFromGRPC(in *BundleRequest) *local.BundleRequest {
	return &local.BundleRequest{
		BundleID:  in.BundleID,
		TargetDir: in.TargetDir,
	}
}

func bundleRequestsToGRPC(in []local.BundleRequest) []*BundleRequest {
	out := make([]*BundleRequest, len(in))
	for i := range in {
		out[i] = bundleRequestToGRPC(in[i])
	}
	return out
}

func bundleRequestsFromGRPC(in []*BundleRequest) []local.BundleRequest {
	out := make([]local.BundleRequest, len(in))
	for i := range in {
		out[i] = *bundleRequestFromGRPC(in[i])
	}
	return out
}
