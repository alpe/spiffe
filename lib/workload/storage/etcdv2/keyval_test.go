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

package etcdv2

import (
	"os"
	"strconv"
	"testing"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/workload"
	"github.com/spiffe/spiffe/lib/workload/suite"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	. "gopkg.in/check.v1"
)

func TestETCD(t *testing.T) { TestingT(t) }

type ESuite struct {
	backend *TempBackend
	suite   suite.WorkloadSuite
}

var _ = Suite(&ESuite{})

func (s *ESuite) SetUpTest(c *C) {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)

	testETCD := os.Getenv(constants.TestETCD)

	if ok, _ := strconv.ParseBool(testETCD); !ok {
		c.Skip("Skipping test suite for ETCD")
		return
	}

	var err error
	s.backend, err = NewTemp(os.Getenv(constants.TestETCDConfig))
	c.Assert(err, IsNil)

	s.suite.C = s.backend.Backend
	s.suite.Clock = s.backend.Clock
	s.suite.S = &workload.CertSigner{
		Collections: s.backend.Backend,
		Clock:       s.suite.Clock,
	}
}

func (s *ESuite) TearDownTest(c *C) {
	if s.backend != nil {
		err := s.backend.Delete()
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
		c.Assert(err, IsNil)
	}
}

func (s *ESuite) TestWorkloadsCRUD(c *C) {
	s.suite.WorkloadsCRUD(c)
}

func (s *ESuite) TestEvents(c *C) {
	s.suite.Events(c)
}

func (s *ESuite) TestCertAuthoritiesCRUD(c *C) {
	s.suite.CertAuthoritiesCRUD(c)
}

func (s *ESuite) TestTrustedRootBundlesCRUD(c *C) {
	s.suite.TrustedRootBundlesCRUD(c)
}

func (s *ESuite) TestPermissionsCRUD(c *C) {
	s.suite.PermissionsCRUD(c)
}

func (s *ESuite) TestSignPermissionsCRUD(c *C) {
	s.suite.SignPermissionsCRUD(c)
}

func (s *ESuite) TestSigner(c *C) {
	s.suite.Signer(c)
}
