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
	"encoding/json"
	"strings"

	"github.com/spiffe/spiffe/workload"

	etcd "github.com/coreos/etcd/client"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

const (
	authoritiesP = "authorities"
)

func New(cfg Config) (*Backend, error) {
	client, err := cfg.NewClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &Backend{client: client, keys: etcd.NewKeysAPI(client), baseKey: cfg.Key}, nil
}

type Backend struct {
	client  etcd.Client
	keys    etcd.KeysAPI
	baseKey string
}

// UpsertCertAuthority updates or inserts certificate authority
// In case if CA can sign, Private
func (b *Backend) UpsertCertAuthority(ctx context.Context, w workload.CertAuthority) error {
	bytes, err := json.Marshal(w)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = b.keys.Set(ctx, b.key(authoritiesP, w.ID), string(bytes), nil)
	return trace.Wrap(convertErr(err))
}

// GetCertAuthority returns Certificate Authority by given ID
func (b *Backend) GetCertAuthority(ctx context.Context, id string) (*workload.CertAuthority, error) {
	if id == "" {
		return nil, trace.BadParameter("missing parameter ID")
	}
	re, err := b.keys.Get(ctx, b.key(authoritiesP, id), nil)
	if err != nil {
		return nil, trace.Wrap(convertErr(err))
	}
	var ca workload.CertAuthority
	err = json.Unmarshal([]byte(re.Node.Value), &ca)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &ca, nil
}

// DeleteCertAuthority deletes Certificate Authority by ID
func (b *Backend) DeleteCertAuthority(id string) error {
	if id == "" {
		return nil, trace.BadParameter("missing parameter ID")
	}
	re, err := b.keys.Delete(ctx, b.key(authoritiesP, id), nil)
	if err != nil {
		return nil, trace.Wrap(convertErr(err))
	}
}

// UpsertWorkload update existing or insert new workload
func (b *Backend) UpsertWorkload(ctx context.Context, w workload.Workload) (*Workload, error) {
}

// DeleteWorkload deletes workload
func (b *Backend) DeleteWorkload(ctx context.Context, ID string) error {
}

// GetWorkload returns workload identified by ID
func (b *Backend) GetWorkload(ctx context.Context, ID string) (*Workload, error) {
}

// Subscribe returns a stream of events associated with given workload IDs
// if you wish to cancel the stream, use ctx.Close
func (b *Backend) Subscribe(ctx context.Context, IDs []string) (<-chan WorkloadEvent, error) {
}

func (b *Backend) key(prefix string, keys ...string) string {
	key := make([]string, 0, len(keys)+2)
	key = append(key, b.baseKey)
	key = append(key, prefix)
	key = append(key, keys...)
	for i := range key {
		key[i] = strings.Replace(key[i], "/", "%2F", -1)
	}
	return strings.Join(key, "/")
}

// convertErr converts error from etcd error to trace error
func convertErr(e error) error {
	if e == nil {
		return nil
	}
	switch err := e.(type) {
	case *etcd.ClusterError:
		return &trace.ConnectionProblemError{Err: err, Message: err.Detail()}
	case etcd.Error:
		switch err.Code {
		case client.ErrorCodeKeyNotFound:
			return &trace.NotFoundError{Message: err.Error()}
		case client.ErrorCodeNotFile:
			return &trace.BadParameterError{Message: err.Error()}
		case client.ErrorCodeNodeExist:
			return &trace.AlreadyExistsError{Message: err.Error()}
		case client.ErrorCodeTestFailed:
			return &trace.CompareFailedError{Message: err.Error()}
		}
	}
	return e
}
