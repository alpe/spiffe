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
	"time"

	"github.com/spiffe/spiffe/lib/identity"

	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

// SetAdminPermissions sets admin permissions for identity
func SetAdminPermissions(ctx context.Context, service Permissions, id identity.ID, signTTL time.Duration) error {
	permissions := []Permission{
		// authorities
		{ID: id, Action: ActionUpsert, Collection: CollectionCertAuthorities},
		{ID: id, Action: ActionRead, Collection: CollectionCertAuthorities},
		{ID: id, Action: ActionDelete, Collection: CollectionCertAuthorities},

		// workloads
		{ID: id, Action: ActionUpsert, Collection: CollectionWorkloads},
		{ID: id, Action: ActionRead, Collection: CollectionWorkloads},
		{ID: id, Action: ActionDelete, Collection: CollectionWorkloads},

		// root bundles
		{ID: id, Action: ActionUpsert, Collection: CollectionTrustedRootBundles},
		{ID: id, Action: ActionRead, Collection: CollectionTrustedRootBundles},
		{ID: id, Action: ActionDelete, Collection: CollectionTrustedRootBundles},

		// permissions
		{ID: id, Action: ActionUpsert, Collection: CollectionPermissions},
		{ID: id, Action: ActionRead, Collection: CollectionPermissions},
		{ID: id, Action: ActionDelete, Collection: CollectionPermissions},

		// sign permissions
		{ID: id, Action: ActionUpsert, Collection: CollectionSignPermissions},
		{ID: id, Action: ActionRead, Collection: CollectionSignPermissions},
		{ID: id, Action: ActionDelete, Collection: CollectionSignPermissions},
	}
	for _, p := range permissions {
		if err := service.UpsertPermission(ctx, p); err != nil {
			return trace.Wrap(err)
		}
	}

	signPermissions := []SignPermission{
		{ID: id, MaxTTL: signTTL},
	}
	for _, sp := range signPermissions {
		if err := service.UpsertSignPermission(ctx, sp); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}
