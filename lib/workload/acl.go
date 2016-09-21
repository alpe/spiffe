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

	// first check if this user has a "blank" sign all permission (admin)
	permission, err := a.Auth.GetSignPermission(ctx, SignPermission{})
	if err != nil {
		if !trace.IsAccessDenied(err) {
			return nil, trace.Wrap(err)
		}
		// check for specific sign permission
		permission, err = a.Auth.GetSignPermission(ctx, SignPermission{
			CertAuthorityID: req.CertAuthorityID,
			Org:             csr.Subject.CommonName,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	if permission.MaxTTL < req.TTL {
		return nil, trace.BadParameter("%v exceeds allowed value of %v", req.TTL, permission.MaxTTL)
	}

	return a.Service.ProcessCertificateRequest(ctx, req)
}

// CreateCertAuthority updates or inserts certificate authority
// In case if CA can sign, Private
func (a *ACL) CreateCertAuthority(ctx context.Context, ca CertAuthority) error {
	if err := a.checkPermission(ctx, ActionUpsert, CollectionCertAuthorities, ca.ID); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.CreateCertAuthority(ctx, ca)
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

// GetCertAuthorityCert returns Certificate Authority (only certificate) by it's ID
func (a *ACL) GetCertAuthorityCert(ctx context.Context, id string) (*CertAuthority, error) {
	if err := a.checkPermission(ctx, ActionReadPublic, CollectionCertAuthorities, id); err != nil {
		if err := a.checkPermission(ctx, ActionRead, CollectionCertAuthorities, id); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.Service.GetCertAuthorityCert(ctx, id)
}

// GetCertAuthoritiesCerts returns Certificate Authority (only certificate) list
func (a *ACL) GetCertAuthoritiesCerts(ctx context.Context) ([]CertAuthority, error) {
	if err := a.checkPermission(ctx, ActionReadPublic, CollectionCertAuthorities, ""); err != nil {
		if err := a.checkPermission(ctx, ActionRead, CollectionCertAuthorities, ""); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.Service.GetCertAuthoritiesCerts(ctx)
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

// UpsertTrustedRootBundle creates or updates trusted root certificate bundle
func (a *ACL) UpsertTrustedRootBundle(ctx context.Context, bundle TrustedRootBundle) error {
	if err := a.checkPermission(ctx, ActionUpsert, CollectionTrustedRootBundles, bundle.ID); err != nil {
		return trace.Wrap(err)
	}
	return a.Service.UpsertTrustedRootBundle(ctx, bundle)
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

// GetTrustedRootBundles returns a list of trusted root bundles
func (a *ACL) GetTrustedRootBundles(ctx context.Context) ([]TrustedRootBundle, error) {
	if err := a.checkPermission(ctx, ActionRead, CollectionTrustedRootBundles, ""); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Service.GetTrustedRootBundles(ctx)
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

// GetWorkloads returns workloads
func (a *ACL) GetWorkloads(ctx context.Context) ([]Workload, error) {
	if err := a.checkPermission(ctx, ActionRead, CollectionWorkloads, ""); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Service.GetWorkloads(ctx)
}

// Subscribe returns a stream of events associated with given workload IDs
// if you wish to cancel the stream, use ctx.Close
// eventC will be closed by Subscribe function on errors or
// cancelled subscribe
func (a *ACL) Subscribe(ctx context.Context, eventC chan *Event) error {
	if err := a.checkPermission(ctx, ActionRead, CollectionWorkloads, ""); err != nil {
		return trace.Wrap(err)
	}
	if err := a.checkPermission(ctx, ActionRead, CollectionCertAuthorities, ""); err != nil {
		if err := a.checkPermission(ctx, ActionReadPublic, CollectionCertAuthorities, ""); err != nil {
			return trace.Wrap(err)
		}
	}
	if err := a.checkPermission(ctx, ActionRead, CollectionTrustedRootBundles, ""); err != nil {
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
