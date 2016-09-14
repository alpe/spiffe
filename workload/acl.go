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

package workload

import (
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
)

// NewService returns new service based on collections interface (usually a backend)
func NewService(collections Collections, clock clockwork.Clock) Service {
	if clock == nil {
		clock = clockwork.NewRealClock()
	}
	return &CertSigner{Collections: collections, Clock: clock}
}

// NewACL wraps service into access controller that checks every action
// against the permissions table
func NewACL(collections Collections, auth PermissionsReader, clock clockwork.Clock) Service {
	return &ACL{
		Auth:    auth,
		Service: NewService(collections, clock),
	}
}

// ACL implements workload interfaces and applies permission checking for them
type ACL struct {
	Auth    PermissionsReader
	Service Service
}

func (a *ACL) checkPermission(ctx context.Context, action, collection, collectionID string) error {
	// check for "all" permission first, regardless of collectionID
	// in case if we have blank permission to read all
	p := Permission{
		Action:     action,
		Collection: collection,
	}
	_, err := a.Auth.GetPermission(ctx, p)
	if err == nil {
		return nil
	}
	if collectionID == "" {
		return trace.Wrap(err)
	}
	p.CollectionID = collectionID
	_, err = a.Auth.GetPermission(ctx, p)
	return err
}

func (a *ACL) ProcessCertificateRequest(ctx context.Context, req CertificateRequest) (*CertificateResponse, error) {
	if err := req.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	csr, err := ParseCertificateRequestPEM(req.CSR)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	permission, err := a.Auth.GetSignPermission(ctx, SignPermission{
		CertAuthorityID: req.CertAuthorityID,
		Org:             csr.Subject.CommonName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if permission.MaxTTL < req.TTL {
		return nil, trace.BadParameter("%v exceeds allowed value of %v", req.TTL, permission.MaxTTL)
	}

	return a.Service.ProcessCertificateRequest(ctx, req)
}

// UpsertCertAuthority updates or inserts certificate authority
// In case if CA can sign, Private
func (a *ACL) UpsertCertAuthority(ctx context.Context, ca CertAuthority) error {
	if err := a.checkPermission(ctx, ActionUpsert, CollectionCertAuthorities, ca.ID); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.UpsertCertAuthority(ctx, ca)
}

// GetCertAuthority returns Certificate Authority by given ID
func (a *ACL) GetCertAuthority(ctx context.Context, id string) (*CertAuthority, error) {
	if err := a.checkPermission(ctx, ActionRead, CollectionCertAuthorities, id); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Service.GetCertAuthority(ctx, id)
}

// DeleteCertAuthority deletes Certificate Authority by ID
func (a *ACL) DeleteCertAuthority(ctx context.Context, id string) error {
	if err := a.checkPermission(ctx, ActionDelete, CollectionCertAuthorities, id); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.DeleteCertAuthority(ctx, id)
}

// CreateTrustedRootBundle creates trusted root certificate bundle
func (a *ACL) CreateTrustedRootBundle(ctx context.Context, bundle TrustedRootBundle) error {
	if err := a.checkPermission(ctx, ActionUpsert, CollectionTrustedRootBundles, bundle.ID); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.CreateTrustedRootBundle(ctx, bundle)
}

// GetTrustedRoot returns trusted root certificate by its ID
func (a *ACL) GetTrustedRootBundle(ctx context.Context, id string) (*TrustedRootBundle, error) {
	if err := a.checkPermission(ctx, ActionRead, CollectionTrustedRootBundles, id); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Service.GetTrustedRootBundle(ctx, id)
}

// DeleteTrustedRootBundle deletes TrustedRoot by its ID
func (a *ACL) DeleteTrustedRootBundle(ctx context.Context, id string) error {
	if err := a.checkPermission(ctx, ActionDelete, CollectionTrustedRootBundles, id); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.DeleteTrustedRootBundle(ctx, id)
}

// UpsertWorkload update existing or insert new workload
func (a *ACL) UpsertWorkload(ctx context.Context, w Workload) error {
	if err := a.checkPermission(ctx, ActionUpsert, CollectionWorkloads, w.ID); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.UpsertWorkload(ctx, w)
}

// DeleteWorkload deletes workload
func (a *ACL) DeleteWorkload(ctx context.Context, id string) error {
	if err := a.checkPermission(ctx, ActionDelete, CollectionWorkloads, id); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.DeleteWorkload(ctx, id)
}

// GetWorkload returns workload identified by ID
func (a *ACL) GetWorkload(ctx context.Context, id string) (*Workload, error) {
	if err := a.checkPermission(ctx, ActionRead, CollectionWorkloads, id); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Service.GetWorkload(ctx, id)
}

// Subscribe returns a stream of events associated with given workload IDs
// if you wish to cancel the stream, use ctx.Close
// eventC will be closed by Subscribe function on errors or
// cancelled subscribe
func (a *ACL) Subscribe(ctx context.Context, eventC chan *WorkloadEvent) error {
	if err := a.checkPermission(ctx, ActionRead, CollectionWorkloads, ""); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.Subscribe(ctx, eventC)
}

// GetSignPermission return permission for actor identified by SPIFFE ID
func (a *ACL) GetSignPermission(ctx context.Context, sp SignPermission) (*SignPermission, error) {
	if err := a.checkPermission(ctx, ActionRead, CollectionSignPermissions, sp.ID.String()); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Service.GetSignPermission(ctx, sp)
}

// UpsertSignPermission updates or inserts permission for actor identified by SPIFFE ID
func (a *ACL) UpsertSignPermission(ctx context.Context, sp SignPermission) error {
	if err := a.checkPermission(ctx, ActionUpsert, CollectionSignPermissions, ""); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.UpsertSignPermission(ctx, sp)
}

// DeleteSignPermission deletes sign permission
func (a *ACL) DeleteSignPermission(ctx context.Context, sp SignPermission) error {
	if err := a.checkPermission(ctx, ActionDelete, CollectionSignPermissions, ""); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.DeleteSignPermission(ctx, sp)
}

// GetPermission returns permission for actor identified by SPIFFE ID
func (a *ACL) GetPermission(ctx context.Context, p Permission) (*Permission, error) {
	if err := a.checkPermission(ctx, ActionRead, CollectionPermissions, ""); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Service.GetPermission(ctx, p)
}

// UpsertPermission updates or inserts permission for actor identified by SPIFFE ID
func (a *ACL) UpsertPermission(ctx context.Context, p Permission) error {
	if err := a.checkPermission(ctx, ActionUpsert, CollectionPermissions, ""); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.UpsertPermission(ctx, p)
}

// DeletePermission deletes permission
func (a *ACL) DeletePermission(ctx context.Context, p Permission) error {
	if err := a.checkPermission(ctx, ActionDelete, CollectionPermissions, ""); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.DeletePermission(ctx, p)
}
