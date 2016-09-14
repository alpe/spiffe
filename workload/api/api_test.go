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

	"github.com/spiffe/spiffe"
	"github.com/spiffe/spiffe/workload"
	"github.com/spiffe/spiffe/workload/storage/etcdv2"
	"github.com/spiffe/spiffe/workload/suite"

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

	testETCD := os.Getenv(spiffe.TestETCD)

	if ok, _ := strconv.ParseBool(testETCD); !ok {
		c.Skip("Skipping test suite for ETCD")
		return
	}

	var err error
	s.backend, err = etcdv2.NewTemp(os.Getenv(spiffe.TestETCDConfig))
	c.Assert(err, IsNil)

	localService := workload.NewService(s.backend.Backend, nil)

	auth, err := NewAuthenticator(s.backend.Backend)
	c.Assert(err, IsNil)
	server, err := NewServer(workload.NewACL(s.backend.Backend, auth, s.backend.Clock))
	c.Assert(err, IsNil)

	ports, err := GetFreeTCPPorts(1)
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
	SetupTLS(config)

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

	client, err := NewClient(NewServiceClient(s.conn))
	c.Assert(err, IsNil)

	s.suite.S = client
	s.suite.C = client
	s.suite.Clock = s.backend.Clock

	permissions := []workload.Permission{
		// authorities
		{ID: suite.AliceID, Action: workload.ActionUpsert, Collection: workload.CollectionCertAuthorities},
		{ID: suite.AliceID, Action: workload.ActionRead, Collection: workload.CollectionCertAuthorities},
		{ID: suite.AliceID, Action: workload.ActionDelete, Collection: workload.CollectionCertAuthorities},

		// workloads
		{ID: suite.AliceID, Action: workload.ActionUpsert, Collection: workload.CollectionWorkloads},
		{ID: suite.AliceID, Action: workload.ActionRead, Collection: workload.CollectionWorkloads},
		{ID: suite.AliceID, Action: workload.ActionDelete, Collection: workload.CollectionWorkloads},

		// root bundles
		{ID: suite.AliceID, Action: workload.ActionUpsert, Collection: workload.CollectionTrustedRootBundles},
		{ID: suite.AliceID, Action: workload.ActionRead, Collection: workload.CollectionTrustedRootBundles},
		{ID: suite.AliceID, Action: workload.ActionDelete, Collection: workload.CollectionTrustedRootBundles},

		// permissions
		{ID: suite.AliceID, Action: workload.ActionUpsert, Collection: workload.CollectionPermissions},
		{ID: suite.AliceID, Action: workload.ActionRead, Collection: workload.CollectionPermissions},
		{ID: suite.AliceID, Action: workload.ActionDelete, Collection: workload.CollectionPermissions},

		// sign permissions
		{ID: suite.AliceID, Action: workload.ActionUpsert, Collection: workload.CollectionSignPermissions},
		{ID: suite.AliceID, Action: workload.ActionRead, Collection: workload.CollectionSignPermissions},
		{ID: suite.AliceID, Action: workload.ActionDelete, Collection: workload.CollectionSignPermissions},
	}
	for _, p := range permissions {
		err = s.backend.Backend.UpsertPermission(context.TODO(), p)
		c.Assert(err, IsNil)
	}

	signPermissions := []workload.SignPermission{
		{ID: suite.AliceID, CertAuthorityID: "example.com", Org: "*.example.com", MaxTTL: 24 * time.Hour},
	}
	for _, sp := range signPermissions {
		err = s.backend.Backend.UpsertSignPermission(context.TODO(), sp)
		c.Assert(err, IsNil)
	}
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

// GetFreeTCPPorts returns a lit of available ports on localhost
// used for testing
func GetFreeTCPPorts(n int) ([]string, error) {
	list := make([]string, 0, n)
	for i := 0; i < n; i++ {
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			return nil, trace.Wrap(err)
		}
		listener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		defer listener.Close()
		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			return nil, trace.BadParameter("Can't get tcp address")
		}
		list = append(list, strconv.Itoa(tcpAddr.Port))
	}
	return list, nil
}

// SetupTLS sets up some modern suites, preference, and min TLS versions
func SetupTLS(config *tls.Config) {
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,

		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}

	config.MinVersion = tls.VersionTLS12
	config.SessionTicketsDisabled = false
	config.ClientSessionCache = tls.NewLRUClientSessionCache(
		1024)
}
