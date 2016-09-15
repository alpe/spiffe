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
	"io"

	"github.com/spiffe/spiffe/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/golang/protobuf/ptypes/empty"
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

// ProcessCertificateRequest process x509 CSR to sign with particular TTL and specifies which CertificateAuthority to use
func (c *Client) ProcessCertificateRequest(ctx context.Context, req workload.CertificateRequest) (*workload.CertificateResponse, error) {
	var header metadata.MD
	re, err := c.Client.ProcessCertificateRequest(ctx, &CertificateRequest{
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

// CreateCertAuthority creates cert authority if it does not exist
func (c *Client) CreateCertAuthority(ctx context.Context, ca workload.CertAuthority) error {
	var header metadata.MD
	_, err := c.Client.CreateCertAuthority(ctx, &CertAuthority{
		ID:         ca.ID,
		Cert:       ca.Cert,
		PrivateKey: ca.PrivateKey,
	}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// UpsertCertAuthority updates or inserts certificate authority
// In case if CA can sign, Private
func (c *Client) UpsertCertAuthority(ctx context.Context, ca workload.CertAuthority) error {
	var header metadata.MD
	_, err := c.Client.UpsertCertAuthority(ctx, &CertAuthority{
		ID:         ca.ID,
		Cert:       ca.Cert,
		PrivateKey: ca.PrivateKey,
	}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// GetCertAuthority returns Certificate Authority by given ID
func (c *Client) GetCertAuthority(ctx context.Context, id string) (*workload.CertAuthority, error) {
	var header metadata.MD
	re, err := c.Client.GetCertAuthority(ctx, &ID{ID: id}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return &workload.CertAuthority{
		ID:         re.ID,
		Cert:       re.Cert,
		PrivateKey: re.PrivateKey,
	}, nil
}

// DeleteCertAuthority deletes Certificate Authority by ID
func (c *Client) DeleteCertAuthority(ctx context.Context, id string) error {
	var header metadata.MD
	_, err := c.Client.DeleteCertAuthority(ctx, &ID{ID: id}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// UpsertWorkload update existing or insert new workload
func (c *Client) UpsertWorkload(ctx context.Context, w workload.Workload) error {
	var header metadata.MD
	out, err := workloadToGRPC(&w)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = c.Client.UpsertWorkload(ctx, out, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// DeleteWorkload deletes workload
func (c *Client) DeleteWorkload(ctx context.Context, id string) error {
	var header metadata.MD
	_, err := c.Client.DeleteWorkload(ctx, &ID{ID: id}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// GetWorkload returns workload identified by ID
func (c *Client) GetWorkload(ctx context.Context, id string) (*workload.Workload, error) {
	var header metadata.MD
	re, err := c.Client.GetWorkload(ctx, &ID{ID: id}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return workloadFromGRPC(re)
}

// Subscribe returns a stream of events associated with given workload IDs
// if you wish to cancel the stream, use ctx.Close
// eventC will be closed by Subscribe function on errors or
// cancelled subscribe
func (c *Client) Subscribe(ctx context.Context, eventC chan *workload.WorkloadEvent) error {
	var header metadata.MD
	stream, err := c.Client.Subscribe(ctx, &empty.Empty{}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	go func() {
		defer func() {
			close(eventC)
		}()
		for {
			event, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				err = trail.FromGRPC(err, header)
				log.Error(trace.DebugReport(err))
				return
			}
			out, err := workloadEventFromGRPC(event)
			if err != nil {
				err = trail.FromGRPC(err, header)
				log.Error(trace.DebugReport(err))
				return
			}
			select {
			case eventC <- out:
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

// CreateTrustedRootBundle creates trusted root certificate bundle
func (c *Client) CreateTrustedRootBundle(ctx context.Context, bundle workload.TrustedRootBundle) error {
	var header metadata.MD
	_, err := c.Client.CreateTrustedRootBundle(ctx, bundleToGRPC(&bundle), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// GetTrustedRoot returns trusted root certificate by its ID
func (c *Client) GetTrustedRootBundle(ctx context.Context, id string) (*workload.TrustedRootBundle, error) {
	var header metadata.MD
	re, err := c.Client.GetTrustedRootBundle(ctx, &ID{ID: id}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return bundleFromGRPC(re), nil
}

// DeleteTrustedRootBundle deletes TrustedRoot by its ID
func (c *Client) DeleteTrustedRootBundle(ctx context.Context, id string) error {
	var header metadata.MD
	_, err := c.Client.DeleteTrustedRootBundle(ctx, &ID{ID: id}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// GetPermission returns permission for actor identified by SPIFFE ID
func (c *Client) GetPermission(ctx context.Context, p workload.Permission) (*workload.Permission, error) {
	var header metadata.MD
	re, err := c.Client.GetPermission(ctx, permissionToGRPC(&p), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return permissionFromGRPC(re)
}

// UpsertPermission updates or inserts permission for actor identified by SPIFFE ID
func (c *Client) UpsertPermission(ctx context.Context, p workload.Permission) error {
	var header metadata.MD
	_, err := c.Client.UpsertPermission(ctx, permissionToGRPC(&p), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// DeletePermission deletes permission
func (c *Client) DeletePermission(ctx context.Context, p workload.Permission) error {
	var header metadata.MD
	_, err := c.Client.DeletePermission(ctx, permissionToGRPC(&p), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// GetSignPermission return permission for actor identified by SPIFFE ID
func (c *Client) GetSignPermission(ctx context.Context, sp workload.SignPermission) (*workload.SignPermission, error) {
	var header metadata.MD
	re, err := c.Client.GetSignPermission(ctx, signPermissionToGRPC(&sp), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return signPermissionFromGRPC(re)
}

// UpsertSignPermission updates or inserts permission for actor identified by SPIFFE ID
func (c *Client) UpsertSignPermission(ctx context.Context, sp workload.SignPermission) error {
	var header metadata.MD
	_, err := c.Client.UpsertSignPermission(ctx, signPermissionToGRPC(&sp), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// DeleteSignPermission deletes sign permission
func (c *Client) DeleteSignPermission(ctx context.Context, sp workload.SignPermission) error {
	var header metadata.MD
	_, err := c.Client.DeleteSignPermission(ctx, signPermissionToGRPC(&sp), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}
