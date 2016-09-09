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

// package suite contains a workload services acceptance test suite
package suite

import (
	"time"

	"github.com/spiffe/spiffe"
	"github.com/spiffe/spiffe/workload"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
	. "gopkg.in/check.v1"
)

var (
	now     = time.Date(2015, 11, 16, 1, 2, 3, 0, time.UTC)
	aliceID = spiffe.MustParseID("urn:spiffe:example.com:user:alice")
	bobID   = spiffe.MustParseID("urn:spiffe:example.com:user:bob")
)

type WorkloadSuite struct {
	C     workload.Collections
	Clock clockwork.FakeClock
}

func (s *WorkloadSuite) WorkloadsCRUD(c *C) {
	w := workload.Workload{
		ID: "dev",
		Identities: []workload.ScopedID{
			{
				ID:        aliceID,
				MaxTTL:    time.Second,
				IsDefault: true,
			},
		},
		TrustedRootIDs: []string{"example.com"},
	}
	ctx := context.TODO()
	err := s.C.UpsertWorkload(ctx, w)
	c.Assert(err, IsNil)

	out, err := s.C.GetWorkload(ctx, w.ID)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, &w)

	err = s.C.DeleteWorkload(ctx, w.ID)
	c.Assert(err, IsNil)
}

func (s *WorkloadSuite) Events(c *C) {
	ctx := context.TODO()
	eventsC := make(chan *workload.WorkloadEvent, 100)
	err := s.C.Subscribe(ctx, eventsC)

	c.Assert(err, IsNil)
	w := workload.Workload{
		ID: "dev",
		Identities: []workload.ScopedID{
			{
				ID:        aliceID,
				MaxTTL:    time.Second,
				IsDefault: true,
			},
		},
		TrustedRootIDs: []string{"example.com"},
	}
	err = s.C.UpsertWorkload(ctx, w)
	c.Assert(err, IsNil)

	select {
	case e := <-eventsC:
		c.Assert(e, DeepEquals, &workload.WorkloadEvent{
			ID:       w.ID,
			Type:     workload.EventWorkloadUpdated,
			Workload: &w,
		})
	case <-time.After(time.Second):
		c.Fatal("timeout waiting for workload update")
	}

	err = s.C.DeleteWorkload(ctx, w.ID)
	c.Assert(err, IsNil)

	_, err = s.C.GetWorkload(ctx, w.ID)
	c.Assert(trace.IsNotFound(err), Equals, true)

	select {
	case e := <-eventsC:
		c.Assert(e, DeepEquals, &workload.WorkloadEvent{
			ID:   w.ID,
			Type: workload.EventWorkloadDeleted,
		})
	case <-time.After(time.Second):
		c.Fatal("timeout waiting for workload update")
	}
}
