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
	"github.com/spiffe/spiffe/lib/local"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func NewClient(conn *grpc.ClientConn) (*Client, error) {
	if conn == nil {
		return nil, trace.BadParameter("missing parameter conn")
	}
	return &Client{Client: NewRenewerClient(conn), conn: conn}, nil
}

// Client is GRPC based Workload service client
type Client struct {
	Client RenewerClient
	conn   *grpc.ClientConn
}

// Close closes underlying connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// CreateBundleRequest creates request to renew certficate bundles in local directory
func (c *Client) CreateBundleRequest(ctx context.Context, r local.BundleRequest) error {
	var header metadata.MD
	_, err := c.Client.CreateBundleRequest(ctx, bundleRequestToGRPC(r), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// CreateCertRequest creates request to sign renew certificates in local directory
func (c *Client) CreateCertRequest(ctx context.Context, r local.CertRequest) error {
	var header metadata.MD
	_, err := c.Client.CreateCertRequest(ctx, certRequestToGRPC(r), grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// DeleteBundleRequest deletes BundleRequest
func (c *Client) DeleteBundleRequest(ctx context.Context, targetDir string) error {
	var header metadata.MD
	_, err := c.Client.DeleteBundleRequest(ctx, &ID{ID: targetDir}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// DeleteCertRequest deletes certificate renewal request
func (c *Client) DeleteCertRequest(ctx context.Context, targetDir string) error {
	var header metadata.MD
	_, err := c.Client.DeleteCertRequest(ctx, &ID{ID: targetDir}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return trace.Wrap(err)
	}
	return nil
}

// GetCertRequests returns a list of cert requests
func (c *Client) GetCertRequests(ctx context.Context) ([]local.CertRequest, error) {
	var header metadata.MD
	re, err := c.Client.GetCertRequests(ctx, &empty.Empty{}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return certRequestsFromGRPC(re.CertRequests)
}

// GetBundleRequests returns a list of bundle requests
func (c *Client) GetBundleRequests(ctx context.Context) ([]local.BundleRequest, error) {
	var header metadata.MD
	re, err := c.Client.GetBundleRequests(ctx, &empty.Empty{}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		return nil, trace.Wrap(err)
	}
	return bundleRequestsFromGRPC(re.BundleRequests), nil
}
