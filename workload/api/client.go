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

// UpsertCertAuthority updates or inserts certificate authority
// In case if CA can sign, Private
func (c *Client) UpsertCertAuthority(ctx context.Context, ca workload.CertAuthority) error {
	panic("not implemented")
}

// GetCertAuthority returns Certificate Authority by given ID
func (c *Client) GetCertAuthority(ctx context.Context, id string) (*workload.CertAuthority, error) {
	panic("not implemented")
}

// DeleteCertAuthority deletes Certificate Authority by ID
func (c *Client) DeleteCertAuthority(ctx context.Context, id string) error {
	panic("not implemented")
}

// CreateTrustedRootBundle creates trusted root certificate bundle
func (c *Client) CreateTrustedRootBundle(ctx context.Context, bundle workload.TrustedRootBundle) error {
	panic("not implemented")
}

// GetTrustedRoot returns trusted root certificate by its ID
func (c *Client) GetTrustedRootBundle(ctx context.Context, id string) (*workload.TrustedRootBundle, error) {
	panic("not implemented")
}

// DeleteTrustedRootBundle deletes TrustedRoot by its ID
func (c *Client) DeleteTrustedRootBundle(ctx context.Context, id string) error {
	panic("not implemented")
}

// UpsertWorkload update existing or insert new workload
func (c *Client) UpsertWorkload(ctx context.Context, w workload.Workload) error {
	panic("not implemented")
}

// DeleteWorkload deletes workload
func (c *Client) DeleteWorkload(ctx context.Context, id string) error {
	panic("not implemented")
}

// GetWorkload returns workload identified by ID
func (c *Client) GetWorkload(ctx context.Context, id string) (*workload.Workload, error) {
	panic("not implemented")
}

// Subscribe returns a stream of events associated with given workload IDs
// if you wish to cancel the stream, use ctx.Close
// eventC will be closed by Subscribe function on errors or
// cancelled subscribe
func (c *Client) Subscribe(ctx context.Context, eventC chan *workload.WorkloadEvent) error {
	panic("not implemented")
}

// GetSignPermission return permission for actor identified by SPIFFE ID
func (c *Client) GetSignPermission(ctx context.Context, sp workload.SignPermission) (*workload.SignPermission, error) {
	panic("not implemented")
}

// UpsertSignPermission updates or inserts permission for actor identified by SPIFFE ID
func (c *Client) UpsertSignPermission(ctx context.Context, sp workload.SignPermission) error {
	panic("not implemented")
}

// DeleteSignPermission deletes sign permission
func (c *Client) DeleteSignPermission(ctx context.Context, sp workload.SignPermission) error {
	panic("not implemented")
}

// GetPermission returns permission for actor identified by SPIFFE ID
func (c *Client) GetPermission(ctx context.Context, p workload.Permission) (*workload.Permission, error) {
	panic("not implemented")
}

// UpsertPermission updates or inserts permission for actor identified by SPIFFE ID
func (c *Client) UpsertPermission(ctx context.Context, p workload.Permission) error {
	panic("not implemented")
}

// DeletePermission deletes permission
func (c *Client) DeletePermission(ctx context.Context, p workload.Permission) error {
	panic("not implemented")
}
