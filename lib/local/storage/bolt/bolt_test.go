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

package bolt

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/local/suite"
	"github.com/spiffe/spiffe/lib/workload"
	"github.com/spiffe/spiffe/lib/workload/storage/etcdv2"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	. "gopkg.in/check.v1"
)

func TestBolt(t *testing.T) { TestingT(t) }

type BoltSuite struct {
	backend     *Bolt
	etcdBackend *etcdv2.TempBackend
	suite       suite.LocalSuite
}

var _ = Suite(&BoltSuite{})

func (s *BoltSuite) SetUpTest(c *C) {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)

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

	s.backend, err = New(Config{
		Path: filepath.Join(dir, "bolt.db"),
	})
	c.Assert(err, IsNil)

	s.suite.R = s.backend
	s.suite.S = localService
}

func (s *BoltSuite) TearDownTest(c *C) {
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

func (s *BoltSuite) TestCertRequestsCRUD(c *C) {
	s.suite.CertRequestsCRUD(c)
}

func (s *BoltSuite) TestBundleRequestsCRUD(c *C) {
	s.suite.BundleRequestsCRUD(c)
}
