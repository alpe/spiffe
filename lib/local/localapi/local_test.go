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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/local"
	"github.com/spiffe/spiffe/lib/local/storage/bolt"
	"github.com/spiffe/spiffe/lib/local/suite"
	"github.com/spiffe/spiffe/lib/workload"
	"github.com/spiffe/spiffe/lib/workload/storage/etcdv2"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"google.golang.org/grpc"
	. "gopkg.in/check.v1"
)

func TestLocalAPI(t *testing.T) { TestingT(t) }

type APISuite struct {
	backend     *bolt.Bolt
	etcdBackend *etcdv2.TempBackend
	suite       suite.LocalSuite
	listener    net.Listener
}

var _ = Suite(&APISuite{})

func (s *APISuite) SetUpTest(c *C) {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	trace.SetDebug(true)

	testETCD := os.Getenv(constants.TestETCD)

	if ok, _ := strconv.ParseBool(testETCD); !ok {
		c.Skip("Skipping test suite for ETCD")
		return
	}

	var err error
	s.etcdBackend, err = etcdv2.NewTemp(os.Getenv(constants.TestETCDConfig))
	c.Assert(err, IsNil)

	localService := workload.NewService(s.etcdBackend.Backend, nil)

	dir := c.MkDir()

	s.backend, err = bolt.New(bolt.Config{
		Path: filepath.Join(dir, "bolt.db"),
	})
	c.Assert(err, IsNil)

	socketAddr := filepath.Join(dir, "server.sock")

	s.listener, err = net.Listen("unix", socketAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	renewerService, err := local.New(local.Config{
		Workload: localService,
		Storage:  s.backend,
	})
	c.Assert(err, IsNil)

	renewerServer, err := NewServer(renewerService)
	c.Assert(err, IsNil)

	server := grpc.NewServer()
	RegisterRenewerServer(server, renewerServer)

	go server.Serve(s.listener)

	conn, err := grpc.Dial("localhost:0", grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, _ time.Duration) (net.Conn, error) {
			return net.Dial("unix", socketAddr)
		}))
	c.Assert(err, IsNil)
	client, err := NewClient(conn)
	c.Assert(err, IsNil)

	s.suite.R = client
	s.suite.S = localService
}

func (s *APISuite) TearDownTest(c *C) {
	if s.etcdBackend != nil {
		err := s.etcdBackend.Delete()
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
		c.Assert(err, IsNil)
	}
	if s.suite.R != nil {
		err := s.suite.R.Close()
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
		c.Assert(err, IsNil)
	}
}

func (s *APISuite) TestCertRequestsCRUD(c *C) {
	s.suite.CertRequestsCRUD(c)
}

func (s *APISuite) TestBundleRequestsCRUD(c *C) {
	s.suite.BundleRequestsCRUD(c)
}
