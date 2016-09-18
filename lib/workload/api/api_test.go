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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/workload"
	"github.com/spiffe/spiffe/lib/workload/storage/etcdv2"
	"github.com/spiffe/spiffe/lib/workload/suite"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	. "gopkg.in/check.v1"
)

func TestRPC(t *testing.T) { TestingT(t) }

type RPCSuite struct {
	backend  *etcdv2.TempBackend
	suite    suite.WorkloadSuite
	doneC    chan error
	listener net.Listener
	conn     *grpc.ClientConn
}

var _ = Suite(&RPCSuite{})

func (s *RPCSuite) SetUpTest(c *C) {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)

	testETCD := os.Getenv(constants.TestETCD)

	if ok, _ := strconv.ParseBool(testETCD); !ok {
		c.Skip("Skipping test suite for ETCD")
		return
	}

	var err error
	s.backend, err = etcdv2.NewTemp(os.Getenv(constants.TestETCDConfig))
	c.Assert(err, IsNil)

	localService := workload.NewService(s.backend.Backend, nil)

	auth, err := NewAuthenticator(s.backend.Backend)
	c.Assert(err, IsNil)
	server, err := NewServer(workload.NewACL(s.backend.Backend, auth, s.backend.Clock))
	c.Assert(err, IsNil)

	ports, err := identity.GetFreeTCPPorts(1)
	c.Assert(err, IsNil)

	listenAddr := fmt.Sprintf("localhost:%v", ports[0])

	ctx := context.TODO()
	ca := workload.CertAuthority{
		ID:         "example.com",
		Cert:       []byte(suite.CertAuthorityCertPEM),
		PrivateKey: []byte(suite.CertAuthorityKeyPEM),
	}
	err = s.backend.Backend.UpsertCertAuthority(ctx, ca)
	c.Assert(err, IsNil)

	signer, err := workload.ParsePrivateKeyPEM([]byte(suite.KeyPEM))
	c.Assert(err, IsNil)
	extension, err := suite.AliceID.X509Extension()
	c.Assert(err, IsNil)

	csr := &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{*extension},
		Subject: pkix.Name{
			Organization: []string{"SPIFFE"},
			CommonName:   "localhost",
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, signer)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	re, err := localService.ProcessCertificateRequest(ctx, workload.CertificateRequest{
		CertAuthorityID: ca.ID,
		CSR:             csrPEM,
		TTL:             time.Hour,
	})
	c.Assert(err, IsNil)

	cert, err := workload.ParseCertificatePEM(re.Cert)
	c.Assert(err, IsNil)
	c.Assert(cert, NotNil)

	tlsCert, err := tls.X509KeyPair(re.Cert, []byte(suite.KeyPEM))
	c.Assert(err, IsNil)

	certAuthorityCert, err := workload.ParseCertificatePEM([]byte(suite.CertAuthorityCertPEM))
	certPool := x509.NewCertPool()
	certPool.AddCert(certAuthorityCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	identity.SetupTLS(config)

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(config)))
	RegisterServiceServer(grpcServer, server)

	log.Infof("listening on %v", listenAddr)
	s.listener, err = net.Listen("tcp", listenAddr)
	c.Assert(err, IsNil)
	s.doneC = make(chan error, 1)

	go func() {
		s.doneC <- trace.Wrap(grpcServer.Serve(s.listener))
	}()

	creds := credentials.NewTLS(config)

	s.conn, err = grpc.Dial(listenAddr, grpc.WithTransportCredentials(creds), grpc.WithBlock(),
		grpc.WithTimeout(time.Second))
	c.Assert(err, IsNil)

	client, err := NewClient(s.conn)
	c.Assert(err, IsNil)

	s.suite.S = client
	s.suite.C = client
	s.suite.Clock = s.backend.Clock

	err = workload.SetAdminPermissions(context.TODO(), s.backend.Backend, suite.AliceID, 24*time.Hour)
	c.Assert(err, IsNil)
}

func (s *RPCSuite) TestWorkloadsCRUD(c *C) {
	s.suite.WorkloadsCRUD(c)
}

func (s *RPCSuite) TestEvents(c *C) {
	s.suite.Events(c)
}

func (s *RPCSuite) TestCertAuthoritiesCRUD(c *C) {
	s.suite.CertAuthoritiesCRUD(c)
}

func (s *RPCSuite) TestTrustedRootBundlesCRUD(c *C) {
	s.suite.TrustedRootBundlesCRUD(c)
}

func (s *RPCSuite) TestPermissionsCRUD(c *C) {
	s.suite.PermissionsCRUD(c)
}

func (s *RPCSuite) TestSignPermissionsCRUD(c *C) {
	s.suite.SignPermissionsCRUD(c)
}

func (s *RPCSuite) TestSigner(c *C) {
	s.suite.Signer(c)
}

func (s *RPCSuite) TearDownTest(c *C) {
	if s.backend != nil {
		err := s.backend.Delete()
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
		c.Assert(err, IsNil)
	}
	if s.listener != nil {
		s.listener.Close()
	}
	select {
	case <-s.doneC:
	case <-time.After(time.Second):
		c.Fatalf("timeout waiting for TLS server shutdown")
	}
	if s.conn != nil {
		s.conn.Close()
	}
}
