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

	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/golang/protobuf/ptypes/empty"
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

func (s *Server) CreateCertAuthority(ctx context.Context, ca *CertAuthority) (*empty.Empty, error) {
	err := s.Service.CreateCertAuthority(ctx, workload.CertAuthority{
		ID:         ca.ID,
		Cert:       ca.Cert,
		PrivateKey: ca.PrivateKey,
	})
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) UpsertCertAuthority(ctx context.Context, ca *CertAuthority) (*empty.Empty, error) {
	err := s.Service.UpsertCertAuthority(ctx, workload.CertAuthority{
		ID:         ca.ID,
		Cert:       ca.Cert,
		PrivateKey: ca.PrivateKey,
	})
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetCertAuthority(ctx context.Context, id *ID) (*CertAuthority, error) {
	ca, err := s.Service.GetCertAuthority(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &CertAuthority{ID: ca.ID, Cert: ca.Cert, PrivateKey: ca.PrivateKey}, nil
}

func (s *Server) DeleteCertAuthority(ctx context.Context, id *ID) (*empty.Empty, error) {
	err := s.Service.DeleteCertAuthority(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) UpsertWorkload(ctx context.Context, w *Workload) (*empty.Empty, error) {
	out, err := workloadFromGRPC(w)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	err = s.Service.UpsertWorkload(ctx, *out)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetWorkload(ctx context.Context, id *ID) (*Workload, error) {
	w, err := s.Service.GetWorkload(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return workloadToGRPC(w)
}

func (s *Server) DeleteWorkload(ctx context.Context, id *ID) (*empty.Empty, error) {
	err := s.Service.DeleteWorkload(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) Subscribe(_ *empty.Empty, stream Service_SubscribeServer) error {
	eventsC := make(chan *workload.WorkloadEvent, 2)
	ctx := stream.Context()
	err := s.Service.Subscribe(ctx, eventsC)
	if err != nil {
		return trail.Send(ctx, err)
	}
	for {
		select {
		case <-ctx.Done():
			log.Debugf("stream is closing")
			return nil
		case event := <-eventsC:
			log.Debugf("got event to send: %v", event)
			out, err := workloadEventToGRPC(event)
			if err != nil {
				log.Error(trace.DebugReport(err))
				return trail.Send(ctx, err)
			}
			log.Debugf("sending to client: %v", out)
			if err := stream.Send(out); err != nil {
				log.Error(trace.DebugReport(err))
				return err
			}
			log.Debugf("sent to client: %v", out)
		}
	}
}

func (s *Server) CreateTrustedRootBundle(ctx context.Context, bundle *TrustedRootBundle) (*empty.Empty, error) {
	err := s.Service.CreateTrustedRootBundle(ctx, *bundleFromGRPC(bundle))
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetTrustedRootBundle(ctx context.Context, id *ID) (*TrustedRootBundle, error) {
	out, err := s.Service.GetTrustedRootBundle(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return bundleToGRPC(out), nil
}

func (s *Server) DeleteTrustedRootBundle(ctx context.Context, id *ID) (*empty.Empty, error) {
	err := s.Service.DeleteTrustedRootBundle(ctx, id.ID)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetPermission(ctx context.Context, in *Permission) (*Permission, error) {
	p, err := permissionFromGRPC(in)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	out, err := s.Service.GetPermission(ctx, *p)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return permissionToGRPC(out), nil
}

func (s *Server) UpsertPermission(ctx context.Context, in *Permission) (*empty.Empty, error) {
	p, err := permissionFromGRPC(in)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	err = s.Service.UpsertPermission(ctx, *p)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) DeletePermission(ctx context.Context, in *Permission) (*empty.Empty, error) {
	p, err := permissionFromGRPC(in)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	err = s.Service.DeletePermission(ctx, *p)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetSignPermission(ctx context.Context, in *SignPermission) (*SignPermission, error) {
	p, err := signPermissionFromGRPC(in)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	out, err := s.Service.GetSignPermission(ctx, *p)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return signPermissionToGRPC(out), nil
}

func (s *Server) UpsertSignPermission(ctx context.Context, in *SignPermission) (*empty.Empty, error) {
	p, err := signPermissionFromGRPC(in)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	err = s.Service.UpsertSignPermission(ctx, *p)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func (s *Server) DeleteSignPermission(ctx context.Context, in *SignPermission) (*empty.Empty, error) {
	p, err := signPermissionFromGRPC(in)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	err = s.Service.DeleteSignPermission(ctx, *p)
	if err != nil {
		return nil, trail.Send(ctx, err)
	}
	return &empty.Empty{}, nil
}

func signPermissionFromGRPC(in *SignPermission) (*workload.SignPermission, error) {
	sid, err := identity.ParseID(in.ID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var signID *identity.ID
	if in.SignID != "" {
		if signID, err = identity.ParseID(in.ID); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return &workload.SignPermission{
		ID:              *sid,
		CertAuthorityID: in.CertAuthorityID,
		Org:             in.Org,
		SignID:          signID,
		MaxTTL:          time.Duration(in.MaxTTL),
	}, nil
}

func signPermissionToGRPC(in *workload.SignPermission) *SignPermission {
	out := SignPermission{
		ID:              in.ID.String(),
		CertAuthorityID: in.CertAuthorityID,
		Org:             in.Org,
		MaxTTL:          int64(in.MaxTTL),
	}
	if in.SignID != nil {
		out.SignID = in.SignID.String()
	}
	return &out
}

func permissionFromGRPC(in *Permission) (*workload.Permission, error) {
	sid, err := identity.ParseID(in.ID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &workload.Permission{
		ID:           *sid,
		Action:       in.Action,
		Collection:   in.Collection,
		CollectionID: in.CollectionID,
	}, nil
}

func permissionToGRPC(in *workload.Permission) *Permission {
	return &Permission{
		ID:           in.ID.String(),
		Action:       in.Action,
		Collection:   in.Collection,
		CollectionID: in.CollectionID,
	}
}

func bundleFromGRPC(in *TrustedRootBundle) *workload.TrustedRootBundle {
	out := workload.TrustedRootBundle{
		ID:    in.ID,
		Certs: make([]workload.TrustedRootCert, len(in.Certs)),
	}
	for i, c := range in.Certs {
		out.Certs[i] = workload.TrustedRootCert{
			ID:       c.ID,
			Filename: c.Filename,
			Cert:     c.Cert,
		}
	}
	return &out
}

func bundleToGRPC(in *workload.TrustedRootBundle) *TrustedRootBundle {
	out := TrustedRootBundle{
		ID:    in.ID,
		Certs: make([]*TrustedRootBundle_TrustedRootCert, len(in.Certs)),
	}
	for i, c := range in.Certs {
		out.Certs[i] = &TrustedRootBundle_TrustedRootCert{
			ID:       c.ID,
			Filename: c.Filename,
			Cert:     c.Cert,
		}
	}
	return &out
}

func workloadEventFromGRPC(in *WorkloadEvent) (*workload.WorkloadEvent, error) {
	out := workload.WorkloadEvent{
		ID:   in.ID,
		Type: in.Type,
	}
	var err error
	if in.Workload != nil {
		out.Workload, err = workloadFromGRPC(in.Workload)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return &out, nil
}

func workloadEventToGRPC(in *workload.WorkloadEvent) (*WorkloadEvent, error) {
	out := WorkloadEvent{
		ID:   in.ID,
		Type: in.Type,
	}
	var err error
	if in.Workload != nil {
		out.Workload, err = workloadToGRPC(in.Workload)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return &out, nil
}

func workloadFromGRPC(in *Workload) (*workload.Workload, error) {
	out := workload.Workload{
		ID:               in.ID,
		TrustedBundleIDs: in.TrustedBundleIDs,
		Identities:       make([]workload.ScopedID, len(in.Identities)),
	}
	for i, id := range in.Identities {
		sid, err := identity.ParseID(id.ID)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out.Identities[i] = workload.ScopedID{
			ID:        *sid,
			IsDefault: id.IsDefault,
			MaxTTL:    time.Duration(id.MaxTTL),
		}
	}
	return &out, nil
}

func workloadToGRPC(in *workload.Workload) (*Workload, error) {
	out := Workload{
		ID:               in.ID,
		TrustedBundleIDs: in.TrustedBundleIDs,
		Identities:       make([]*Workload_ScopedID, len(in.Identities)),
	}
	for i, id := range in.Identities {
		out.Identities[i] = &Workload_ScopedID{
			ID:        id.ID.String(),
			IsDefault: id.IsDefault,
			MaxTTL:    int64(id.MaxTTL),
		}
	}
	return &out, nil
}
