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

// package etcdv2 implements etcd V2 client backend for workload API
package etcdv2

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/spiffe/spiffe/workload"

	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/client"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

const (
	DefaultBackoffPeriod = time.Second
	authoritiesP         = "authorities"
	bundlesP             = "bundles"
	permissionsP         = "permissions"
	signPermissionsP     = "signpermissions"
	workloadsP           = "workloads"
	allCollections       = "___all___"
)

func New(cfg Config) (*Backend, error) {
	client, err := cfg.NewClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if cfg.BackoffPeriod == 0 {
		cfg.BackoffPeriod = DefaultBackoffPeriod
	}
	return &Backend{
		client:        client,
		keys:          etcd.NewKeysAPI(client),
		baseKey:       strings.Split(cfg.Key, "/"),
		backoffPeriod: cfg.BackoffPeriod}, nil
}

type Backend struct {
	client        etcd.Client
	keys          etcd.KeysAPI
	baseKey       []string
	backoffPeriod time.Duration
}

// UpsertCertAuthority updates or inserts certificate authority
// In case if CA can sign, Private
func (b *Backend) UpsertCertAuthority(ctx context.Context, w workload.CertAuthority) error {
	data, err := marshal(w)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = b.keys.Set(ctx, b.key(authoritiesP, w.ID), data, nil)
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
	err = unmarshal(re.Node.Value, &ca)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &ca, nil
}

// DeleteCertAuthority deletes Certificate Authority by ID
func (b *Backend) DeleteCertAuthority(ctx context.Context, id string) error {
	if id == "" {
		return trace.BadParameter("missing parameter ID")
	}
	_, err := b.keys.Delete(ctx, b.key(authoritiesP, id), nil)
	return trace.Wrap(convertErr(err))
}

// UpsertWorkload update existing or insert new workload
func (b *Backend) UpsertWorkload(ctx context.Context, w workload.Workload) error {
	if err := w.Check(); err != nil {
		return trace.Wrap(err)
	}
	data, err := marshal(w)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = b.keys.Set(ctx, b.key(workloadsP, w.ID), data, nil)
	if err != nil {
		return trace.Wrap(convertErr(err))
	}
	return nil
}

// DeleteWorkload deletes workload
func (b *Backend) DeleteWorkload(ctx context.Context, id string) error {
	if id == "" {
		return trace.BadParameter("missing parameter ID")
	}
	_, err := b.keys.Delete(ctx, b.key(workloadsP, id), nil)
	return trace.Wrap(convertErr(err))
}

// GetWorkload returns workload identified by ID
func (b *Backend) GetWorkload(ctx context.Context, id string) (*workload.Workload, error) {
	if id == "" {
		return nil, trace.BadParameter("missing parameter id")
	}
	re, err := b.keys.Get(ctx, b.key(workloadsP, id), nil)
	if err != nil {
		return nil, trace.Wrap(convertErr(err))
	}
	var w workload.Workload
	err = unmarshal(re.Node.Value, &w)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &w, nil
}

func (b *Backend) getWatchAtLatestIndex(ctx context.Context, key string) (etcd.Watcher, *etcd.Response, error) {
	re, err := b.keys.Get(ctx, key, nil)
	err = convertErr(err)
	if err == nil {
		return b.keys.Watcher(key, &etcd.WatcherOptions{
			AfterIndex: re.Node.ModifiedIndex,
			Recursive:  true,
		}), re, nil
	}
	if !trace.IsNotFound(err) {
		return nil, nil, trace.Wrap(err)
	}
	re, err = b.keys.Set(
		ctx, key, "",
		&etcd.SetOptions{PrevExist: etcd.PrevNoExist, Dir: true})
	err = convertErr(err)
	if err != nil {
		if !trace.IsAlreadyExists(err) {
			return nil, nil, trace.Wrap(err)
		}
		re, err = b.keys.Get(ctx, key, nil)
		if err = convertErr(err); err != nil {
			return nil, nil, trace.Wrap(err)
		}
	}
	return b.keys.Watcher(key, &etcd.WatcherOptions{
		AfterIndex: re.Node.ModifiedIndex,
		Recursive:  true,
	}), re, nil
}

func marshal(val interface{}) (string, error) {
	data, err := json.Marshal(val)
	if err != nil {
		return "", trace.BadParameter("failed to marshal '%v': %v", val, err)
	}
	return string(data), nil
}

func unmarshal(data string, val interface{}) error {
	if data == "" {
		return trace.BadParameter("empty value to unmarshal")
	}
	err := json.Unmarshal([]byte(data), val)
	if err != nil {
		return trace.BadParameter("failed to unmarshal '%v': %v", data, err)
	}
	return nil
}

func processWorkloadEvent(ctx context.Context, prefix string, re *etcd.Response, eventsC chan *workload.WorkloadEvent) {
	// set, delete, update, create, compareAndSwap, compareAndDelete and expire.
	if !strings.HasPrefix(re.Node.Key, prefix) {
		log.Debugf("skipping non-workload event: %v", re.Node.Key)
		return
	}
	workloadID := strings.TrimPrefix(re.Node.Key, prefix+"/")
	if strings.Contains(workloadID, "/") {
		log.Debugf("skipping non-workload event: %v", re.Node.Key)
		return
	}
	var event *workload.WorkloadEvent
	switch re.Action {
	case "delete", "expire", "compareAndDelete":
		event = &workload.WorkloadEvent{
			ID:   workloadID,
			Type: workload.EventWorkloadDeleted,
		}
	case "set", "update", "create", "compareAndSwap":
		var w workload.Workload
		err := unmarshal(re.Node.Value, &w)
		if err != nil {
			log.Error(trace.DebugReport(err))
			return
		}
		event = &workload.WorkloadEvent{
			ID:       workloadID,
			Type:     workload.EventWorkloadUpdated,
			Workload: &w,
		}
	default:
		log.Debugf("unsupported event action: %v", re.Action)
		return
	}
	select {
	case eventsC <- event:
		log.Infof("sent event %#v", event)
	case <-ctx.Done():
		log.Infof("client is closing")
	default:
		log.Warningf("blocked on sending to subscriber, possible deadlock")
	}
}

// Subscribe returns a stream of events associated with given workload IDs
// if you wish to cancel the stream, use ctx.Close
func (b *Backend) Subscribe(ctx context.Context, eventC chan *workload.WorkloadEvent) error {
	workloadsKey := b.key(workloadsP)
	watcher, re, err := b.getWatchAtLatestIndex(ctx, workloadsKey)
	if err != nil {
		return trace.Wrap(err)
	}
	go func() {
		ticker := time.NewTicker(b.backoffPeriod)
		defer ticker.Stop()
		defer func() {
			close(eventC)
		}()
		for {
			re, err = watcher.Next(ctx)
			if err == nil {
				log.Infof("processWorkloadEvent(%v,%v)", re.Action, re.Node.Key)
				processWorkloadEvent(ctx, workloadsKey, re, eventC)
			}
			if err != nil {
				select {
				case <-ticker.C:
					log.Infof("backoff on error %v", trace.DebugReport(err))
				}
				if err == context.Canceled {
					log.Infof("client is closing, return")
					return
				} else if cerr, ok := err.(*etcd.ClusterError); ok {
					if len(cerr.Errors) != 0 && cerr.Errors[0] == context.Canceled {
						log.Infof("client is closing, return")
						return
					}
					log.Errorf("unexpected cluster error: %v (%v)", trace.DebugReport(err), cerr.Detail())
					continue
				} else if cerr, ok := err.(etcd.Error); ok && cerr.Code == etcd.ErrorCodeEventIndexCleared {
					log.Infof("watch index error, resetting watch index: %v", cerr)
					watcher, re, err = b.getWatchAtLatestIndex(ctx, workloadsKey)
					if err != nil {
						continue
					}
				} else {
					log.Errorf("unexpected watch error: %v", trace.DebugReport(err))
					watcher, re, err = b.getWatchAtLatestIndex(ctx, workloadsKey)
					if err != nil {
						continue
					}
				}
			}
			select {
			case <-ctx.Done():
				log.Infof("context is closing, return")
				return
			default:
			}
		}
	}()
	return nil
}

// UpsertPermission updates or inserts permission for actor identified by SPIFFE ID
func (b *Backend) UpsertPermission(ctx context.Context, p workload.Permission) error {
	key, err := b.permKey(p)
	if err != nil {
		return trace.Wrap(err)
	}
	val, err := marshal(p)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = b.keys.Set(ctx, key, val, nil)
	return trace.Wrap(convertErr(err))
}

// GetPermission return list permissions for actor identified by SPIFFE ID
func (b *Backend) GetPermission(ctx context.Context, p workload.Permission) (*workload.Permission, error) {
	key, err := b.permKey(p)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	re, err := b.keys.Get(ctx, key, nil)
	if err = convertErr(err); err != nil {
		return nil, trace.Wrap(err)
	}
	var out workload.Permission
	if err = unmarshal(re.Node.Value, &out); err != nil {
		return nil, trace.Wrap(err)
	}
	return &out, nil
}

// DeletePermission deletes permission
func (b *Backend) DeletePermission(ctx context.Context, p workload.Permission) error {
	key, err := b.permKey(p)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = b.keys.Delete(ctx, key, nil)
	return trace.Wrap(convertErr(err))
}

// UpsertSignPermission updates or inserts permission for actor identified by SPIFFE ID
func (b *Backend) UpsertSignPermission(ctx context.Context, s workload.SignPermission) error {
	if err := s.Check(); err != nil {
		return trace.Wrap(err)
	}
	val, err := marshal(s)
	if err != nil {
		return trace.Wrap(err)
	}
	if s.Org == allCollections || s.CertAuthorityID == allCollections {
		return trace.BadParameter("reserved value %v", allCollections)
	}
	var org, certAuthorityID, signID string
	if s.SignID != nil {
		signID = s.SignID.String()
	} else {
		signID = allCollections
	}
	if s.Org == "" {
		org = allCollections
	} else {
		org = s.Org
	}
	if s.CertAuthorityID == "" {
		certAuthorityID = allCollections
	} else {
		certAuthorityID = s.CertAuthorityID
	}
	_, err = b.keys.Set(ctx, b.key(
		signPermissionsP, s.ID.String(), certAuthorityID, org, signID), val, nil)
	if err = convertErr(err); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetSignPermissions returns list of permissions for actor identified by SPIFFE ID
func (b *Backend) GetSignPermission(ctx context.Context, sp workload.SignPermission) (*workload.SignPermission, error) {
	key, err := b.signKey(sp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	re, err := b.keys.Get(ctx, key, nil)
	if err = convertErr(err); err != nil {
		return nil, trace.Wrap(err)
	}
	var p workload.SignPermission
	if err := unmarshal(re.Node.Value, &p); err != nil {
		return nil, trace.Wrap(err)
	}
	return &p, nil
}

// DeleteSignPermission deletes sign permission
func (b *Backend) DeleteSignPermission(ctx context.Context, sp workload.SignPermission) error {
	key, err := b.signKey(sp)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = b.keys.Delete(ctx, key, nil)
	return trace.Wrap(convertErr(err))
}

// CreateTrustedRootBundle creates trusted root certificate bundle
func (b *Backend) CreateTrustedRootBundle(ctx context.Context, bundle workload.TrustedRootBundle) error {
	if err := bundle.Check(); err != nil {
		return trace.Wrap(err)
	}
	val, err := marshal(bundle)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = b.keys.Set(ctx, b.key(bundlesP, bundle.ID), val, &etcd.SetOptions{PrevExist: etcd.PrevNoExist})
	if err = convertErr(err); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetTrustedRootBundle returns trusted root certificate bundle by its ID
func (b *Backend) GetTrustedRootBundle(ctx context.Context, id string) (*workload.TrustedRootBundle, error) {
	if id == "" {
		return nil, trace.BadParameter("missing parameter ID")
	}
	re, err := b.keys.Get(ctx, b.key(bundlesP, id), nil)
	if err = convertErr(err); err != nil {
		return nil, trace.Wrap(err)
	}
	var bundle workload.TrustedRootBundle
	if err := unmarshal(re.Node.Value, &bundle); err != nil {
		return nil, trace.Wrap(err)
	}
	return &bundle, nil
}

// DeleteTrustedRootBundle deletes TrustedRootBundle by its ID
func (b *Backend) DeleteTrustedRootBundle(ctx context.Context, id string) error {
	if id == "" {
		return trace.BadParameter("missing parameter ID")
	}
	_, err := b.keys.Delete(ctx, b.key(bundlesP, id), nil)
	return trace.Wrap(convertErr(err))
}

func (b *Backend) key(prefix string, keys ...string) string {
	key := make([]string, 0, len(keys)+2)
	key = append(key, b.baseKey...)
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
		case etcd.ErrorCodeKeyNotFound:
			return &trace.NotFoundError{Message: err.Error()}
		case etcd.ErrorCodeNotFile:
			return &trace.BadParameterError{Message: err.Error()}
		case etcd.ErrorCodeNodeExist:
			return &trace.AlreadyExistsError{Message: err.Error()}
		case etcd.ErrorCodeTestFailed:
			return &trace.CompareFailedError{Message: err.Error()}
		}
	}
	return e
}

type signPermissionKey struct {
	id              string
	org             string
	signID          string
	certAuthorityID string
}

func (b *Backend) signKey(s workload.SignPermission) (string, error) {
	if err := s.Check(); err != nil {
		return "", trace.Wrap(err)
	}
	if s.Org == allCollections || s.CertAuthorityID == allCollections {
		return "", trace.BadParameter("reserved value %v", allCollections)
	}
	key := &signPermissionKey{id: s.ID.String()}
	if s.SignID != nil {
		key.signID = s.SignID.String()
	} else {
		key.signID = allCollections
	}
	if s.Org == "" {
		key.org = allCollections
	} else {
		key.org = s.Org
	}
	if s.CertAuthorityID == "" {
		key.certAuthorityID = allCollections
	} else {
		key.certAuthorityID = s.CertAuthorityID
	}
	return b.key(
		signPermissionsP, key.id, key.certAuthorityID, key.org, key.signID), nil
}

type permissionKey struct {
	id           string
	action       string
	collection   string
	collectionID string
}

func (b *Backend) permKey(p workload.Permission) (string, error) {
	if err := p.Check(); err != nil {
		return "", trace.Wrap(err)
	}
	if p.CollectionID == allCollections {
		return "", trace.BadParameter("reserved value %v", allCollections)
	}
	key := &permissionKey{
		id:         p.ID.String(),
		action:     p.Action,
		collection: p.Collection,
	}
	if p.CollectionID == "" {
		key.collectionID = allCollections
	} else {
		key.collectionID = p.CollectionID
	}
	return b.key(
		permissionsP, key.id, key.action, key.collection, key.collectionID), nil
}
