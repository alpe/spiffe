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
	"path/filepath"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/toolbox"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
)

// BundleWriter specifies a method to write trusted root bundle
type BundleWriter func(ctx context.Context, certAuthorities Authorities, bundle *TrustedRootBundle) error

// BundleRenewerConfig configures certificate bundle renewer
type BundleRenewerConfig struct {
	// TrustedRootBundleID is ID of the trusted root bundle to renew
	TrustedRootBundleID string
	// Clock is an interface to time functions, useful in tests
	Clock clockwork.Clock
	// Service is a workload service
	Service Service
	// WriteBundle implements tool to write bundles
	WriteBundle BundleWriter
	// EventsC is a channel for notifications about renewed bundles
	EventsC chan *TrustedRootBundle
	// Entry is a logger entry
	Entry *log.Entry
}

// CheckAndSetDefaults checks config params and sets some default values
func (c *BundleRenewerConfig) CheckAndSetDefaults() error {
	if c.TrustedRootBundleID == "" {
		return trace.BadParameter("missing parmeter TrustedRootBundleID")
	}
	if c.Service == nil {
		return trace.BadParameter("missing parmeter Service")
	}
	if c.WriteBundle == nil {
		return trace.BadParameter("missing parameter WriteBundle")
	}
	if c.Entry == nil {
		return trace.BadParameter("missing parameter Entry")
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	return nil
}

// BundleRenewer listens to updates in trusted root bundle
type BundleRenewer struct {
	*log.Entry
	BundleRenewerConfig
}

// NewBundleRenewer returns new instance of certificate renewer
func NewBundleRenewer(config BundleRenewerConfig) (*BundleRenewer, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &BundleRenewer{
		BundleRenewerConfig: config,
		Entry:               config.Entry,
	}, nil
}

// Write is a one-time writer of the bundle
func (r *BundleRenewer) Write(ctx context.Context, bundle *TrustedRootBundle) error {
	err := r.WriteBundle(ctx, r.Service, bundle)
	if err != nil {
		return trace.Wrap(err)
	}
	if r.EventsC != nil {
		select {
		case r.EventsC <- bundle:
			return nil
		default:
			return trace.ConnectionProblem(nil, "failed to send event")
		}
	}
	return nil
}

// Start starts renewer procedure, it is a blocking call,
// to cancel, simply use context cancelling ability
func (r *BundleRenewer) Start(ctx context.Context) error {
	bundle, err := r.Service.GetTrustedRootBundle(ctx, r.TrustedRootBundleID)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := r.Write(ctx, bundle); err != nil {
		return trace.Wrap(err)
	}

	eventsC := make(chan *Event, 1)
	subscribeContext, cancelWatch := context.WithCancel(ctx)
	err = r.Service.Subscribe(subscribeContext, eventsC)
	if err != nil {
		return trace.Wrap(err)
	}
	defer cancelWatch()

	for {
		select {
		case event := <-eventsC:
			if event.Type == EventTypeTrustedRootBundle && event.ID == r.TrustedRootBundleID {
				if event.Action == EventActionDeleted {
					r.Debugf("Bundle %v vanished, stop updates", r.TrustedRootBundleID)
					return nil
				} else if event.Action == EventActionUpdated {
					r.Debugf("Bundle %v updated, write bundles", r.TrustedRootBundleID)
					if err := r.Write(ctx, event.Bundle); err != nil {
						return trace.Wrap(err)
					}
				}
			}
		case <-ctx.Done():
			r.Debugf("context is closing, returning")
			return nil
		}
	}
}

// WriteBunldeToDirectory writes bundle certificates to directory
func WriteBundleToDirectory(ctx context.Context, targetDir string, certAuthorities Authorities, bundle *TrustedRootBundle) error {
	if _, err := toolbox.StatDir(targetDir); err != nil {
		return trace.Wrap(err)
	}
	var certs []CertAuthority
	for _, id := range bundle.CertAuthorityIDs {
		cert, err := certAuthorities.GetCertAuthorityCert(ctx, id)
		if err != nil {
			return trace.Wrap(err)
		}
		certs = append(certs, *cert)
	}

	// write certs from cert authorities first
	for _, cert := range certs {
		err := toolbox.WritePath(filepath.Join(targetDir, "certauthority", cert.ID)+".pem", cert.Cert, constants.DefaultSharedFileMask)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// write bundle external certs
	for _, cert := range bundle.Certs {
		filename := cert.Filename
		if filename == "" {
			filename = filepath.Join("cert", cert.ID) + ".pem"
		}
		err := toolbox.WritePath(filepath.Join(targetDir, filename), cert.Cert, constants.DefaultSharedFileMask)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}
