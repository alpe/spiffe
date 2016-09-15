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
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"

	"github.com/gravitational/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ServerConfig struct {
	TLSKey  []byte
	TLSCert []byte
	TLSCA   []byte
	// Implementation of a Service
	Server ServiceServer
}

// CheckAndSetDefaults checks config parmeters and sets some defaults
func (c *ServerConfig) CheckAndSetDefaults() error {
	if len(c.TLSKey) == 0 {
		return trace.BadParameter("missing parameter TLSKey")
	}
	if len(c.TLSCert) == 0 {
		return trace.BadParameter("missing parameter TLSCert")
	}
	if len(c.TLSCA) == 0 {
		return trace.BadParameter("missing parameter TLSCA")
	}
	if c.Server == nil {
		return trace.BadParameter("missing parameter Server")
	}
	return nil
}

// NewServerFromConfig creates new GRPC server from configuration
func NewServerFromConfig(config ServerConfig) (*grpc.Server, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	tlsCert, err := tls.X509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(config.TLSCA); !ok {
		return nil, trace.BadParameter("failed to parse TLS certificate authority fields")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	identity.SetupTLS(tlsConfig)

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	RegisterServiceServer(grpcServer, config.Server)
	return grpcServer, nil
}

// ClientConfig specifies configuration to create TLS GRPC client
type ClientConfig struct {
	TargetAddr  string
	TLSKey      []byte
	TLSCert     []byte
	TLSCA       []byte
	DialTimeout time.Duration
}

// CheckAndSetDefaults checks config parmeters and sets some defaults
func (c *ClientConfig) CheckAndSetDefaults() error {
	if c.DialTimeout == 0 {
		c.DialTimeout = constants.DefaultDialTimeout
	}
	if c.TargetAddr == "" {
		return trace.BadParameter("missing parameter TargetAddr")
	}
	if len(c.TLSKey) == 0 {
		return trace.BadParameter("missing parameter TLSKey")
	}
	if len(c.TLSCert) == 0 {
		return trace.BadParameter("missing parameter TLSCert")
	}
	if len(c.TLSCA) == 0 {
		return trace.BadParameter("missing parameter TLSCA")
	}
	return nil
}

// NewClientFromConfig returns new client from config parameters
func NewClientFromConfig(config ClientConfig) (*Client, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	tlsCert, err := tls.X509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(config.TLSCA); !ok {
		return nil, trace.BadParameter("failed to parse TLS certificate authority fields")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	identity.SetupTLS(tlsConfig)

	creds := credentials.NewTLS(tlsConfig)

	conn, err := grpc.Dial(config.TargetAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(config.DialTimeout))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewClient(conn)
}
