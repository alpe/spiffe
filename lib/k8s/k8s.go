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

// package k8s implemenets k8s-native plugin for client and server.
// K8s integration service watches for K8s namespaces, if new namespace
// is created, the service does the following:
//
// * Sets up TLS Certificate Authority for this namespace
// * Adds special identity that is authorized to sign certificates for this
// certificate authority (*.kube-system.svc.cluster.local) matching subdomain
// assigned for this namespace
// * Creates (and mantains) secret in this namespace that contains certificate
//   and private key authenticated as SPIFFE identity assigned to the cluster
//   and certificate authority certificate to be trusted
//
// SPIFFE node can use GetKeyPair
package k8s

import (
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/errors"
	"k8s.io/client-go/1.4/pkg/api/meta"
	"k8s.io/client-go/1.4/pkg/api/v1"
	"k8s.io/client-go/1.4/pkg/watch"
	"k8s.io/client-go/1.4/rest"
)

// ServiceConfig is a config for K8s integration service
type ServiceConfig struct {
	Service workload.Service
}

// NewService returns new instance of K8s integration service
func NewService(cfg ServiceConfig) (*Service, error) {
	client, err := GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &Service{
		client:        client,
		ServiceConfig: cfg,
		Entry:         log.WithFields(log.Fields{trace.Component: constants.ComponentSPIFFE}),
		renewers:      make(map[string]*renewerBundle),
	}, nil
}

// Service is K8s integration service. It is started in K8s mode
// and watches K8s namespaces setting up proper TLS infrastructure for them
type Service struct {
	sync.Mutex
	client *kubernetes.Clientset
	ServiceConfig
	*log.Entry
	renewers map[string]*renewerBundle
}

// GetClient returns new K8s in-cluster client
func GetClient() (*kubernetes.Clientset, error) {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return clientset, nil
}

// ReadKeyPairFromSecret reads key pair directly from K8s secret
func ReadKeyPairFromSecret(namespace string, name string) (*workload.KeyPair, error) {
	client, err := GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	secretRW := &secretRW{namespace: namespace, secretName: name, client: client}
	return secretRW.ReadKeyPair()
}

// Serve is a blocking call that launches the service
func (s *Service) Serve(ctx context.Context) {
	for {
		err := s.watchNamespaces(ctx)
		if err != nil {
			log.Error(trace.DebugReport(err))
		} else {
			s.Infof("context is closing")
		}
		select {
		case <-ctx.Done():
			s.Infof("context is closing")
		case <-time.After(constants.DefaultReconnectPeriod):
			continue
		}
	}
}

func (s *Service) deleteCertAuthority(ctx context.Context, namespace kubeNamespace) error {
	return s.Service.DeleteCertAuthority(ctx, namespace.CertAuthorityID())
}

func (s *Service) deleteRenewer(ctx context.Context, namespace kubeNamespace) error {
	s.Lock()
	defer s.Unlock()
	r, ok := s.renewers[string(namespace)]
	if !ok {
		s.Infof("%v renewer not found")
		return nil
	}
	r.cancelFunc()
	go func() {
		err := r.secretRW.DeleteKeyPair()
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()
	delete(s.renewers, string(namespace))
	return nil
}

func (s *Service) startRenewer(ctx context.Context, namespace kubeNamespace) error {
	s.Lock()
	defer s.Unlock()
	if _, ok := s.renewers[string(namespace)]; ok {
		s.Infof("%v renewer already exists", namespace)
		return nil
	}
	s.Infof("creating new renewer %v", namespace)
	r, err := s.newRenewer(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	s.renewers[string(namespace)] = r
	return nil
}

func (s *Service) installCertAuthority(ctx context.Context, namespace kubeNamespace) error {
	s.Debugf("installCertAuthority")
	err := s.upsertCertAuthority(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.upsertPermissions(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.upsertBundle(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.startRenewer(ctx, namespace)
	return trace.Wrap(err)
}

func (s *Service) uninstallCertAuthority(ctx context.Context, namespace kubeNamespace) error {
	err := s.deleteCertAuthority(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.deletePermissions(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.deleteBundle(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.deleteRenewer(ctx, namespace)
	return trace.Wrap(err)
}

func (s *Service) upsertBundle(ctx context.Context, namespace kubeNamespace) error {
	s.Debugf("upsertBundle")
	err := s.Service.UpsertTrustedRootBundle(ctx, namespace.Bundle())
	return trace.Wrap(err)
}

func (s *Service) deleteBundle(ctx context.Context, namespace kubeNamespace) error {
	s.Debugf("deleteBundle")
	err := s.Service.DeleteTrustedRootBundle(ctx, namespace.BundleID())
	return trace.Wrap(err)
}

func (s *Service) upsertPermissions(ctx context.Context, namespace kubeNamespace) error {
	s.Debugf("upsertPermissions")
	for _, p := range namespace.Permissions() {
		if err := s.Service.UpsertPermission(ctx, p); err != nil {
			return trace.Wrap(err)
		}
	}

	for _, sp := range namespace.SignPermissions() {
		err := s.Service.UpsertSignPermission(ctx, sp)
		s.Debugf("upsertSignPermission %v, err: %v", sp, err)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (s *Service) deletePermissions(ctx context.Context, namespace kubeNamespace) error {
	for _, p := range namespace.Permissions() {
		if err := s.Service.DeletePermission(ctx, p); err != nil {
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}

		}
	}

	for _, sp := range namespace.SignPermissions() {
		if err := s.Service.DeleteSignPermission(ctx, sp); err != nil {
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
		}
	}
	return nil
}

func (s *Service) upsertCertAuthority(ctx context.Context, namespace kubeNamespace) error {
	s.Infof("upsertCertAuthority(namespace=%v)", namespace)
	_, err := s.Service.GetCertAuthorityCert(ctx, namespace.CertAuthorityID())
	if err == nil {
		return nil
	}
	if !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	keyPEM, certPEM, err := identity.GenerateSelfSignedCA(pkix.Name{
		CommonName:   namespace.CommonName(),
		Organization: []string{namespace.Org()},
	}, nil, constants.DefaultCATTL)
	if err != nil {
		return trace.Wrap(err)
	}
	certAuthority := workload.CertAuthority{
		ID:         namespace.CertAuthorityID(),
		PrivateKey: keyPEM,
		Cert:       certPEM,
	}
	err = s.Service.CreateCertAuthority(ctx, certAuthority)
	if err != nil {
		if !trace.IsAlreadyExists(err) {
			return trace.Wrap(err)
		}
	}

	return nil
}

func (s *Service) watchNamespaces(ctx context.Context) error {
	namespaces, err := s.client.Core().Namespaces().List(api.ListOptions{})
	if err != nil {
		return trace.Wrap(err)
	}
	for _, namespace := range namespaces.Items {
		err = s.installCertAuthority(ctx, kubeNamespace(namespace.Name))
		if err != nil {
			return trace.Wrap(err)
		}
	}

	watcher, err := s.client.Core().Namespaces().Watch(api.ListOptions{})
	if err != nil {
		return trace.Wrap(err)
	}
	defer watcher.Stop()

	accessor := meta.NewAccessor()

	eventsC := watcher.ResultChan()
	for {
		select {
		case event := <-eventsC:
			if event.Type == watch.Error {
				s.Warningf("unsupported event: %#v", event)
			}
			namespace, err := accessor.Name(event.Object)
			if err != nil {
				return trace.Wrap(err)
			}
			if event.Type == watch.Added || event.Type == watch.Modified {
				if err := s.installCertAuthority(ctx, kubeNamespace(namespace)); err != nil {
					return trace.Wrap(err)
				}
			}
			if event.Type == watch.Deleted {
				if err := s.uninstallCertAuthority(ctx, kubeNamespace(namespace)); err != nil {
					return trace.Wrap(err)
				}
			}
		case <-ctx.Done():
			s.Infof("context is closing")
			return nil
		}
	}
}

func (s *Service) newRenewer(ctx context.Context, namespace kubeNamespace) (*renewerBundle, error) {
	renewerContext, cancelFunc := context.WithCancel(ctx)

	secretRW := &secretRW{
		client:     s.client,
		secretName: namespace.SecretID(),
		namespace:  string(namespace),
	}

	renewer, err := workload.NewCertRenewer(workload.CertRenewerConfig{
		Entry: log.WithFields(log.Fields{
			trace.Component: constants.ComponentSPIFFE,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: constants.AdminOrg,
			ID:              namespace.ID(),
			Subject: pkix.Name{
				CommonName: namespace.CommonName(),
			},
			TTL: constants.DefaultLocalCertTTL,
		},
		ReadKeyPair:  secretRW.ReadKeyPair,
		WriteKeyPair: secretRW.WriteKeyPair,
		Service:      s.Service,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	go func() {
		err := renewer.Start(renewerContext)
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()
	return &renewerBundle{renewer: renewer, cancelFunc: cancelFunc, secretRW: secretRW}, nil
}

type renewerBundle struct {
	renewer    *workload.CertRenewer
	cancelFunc context.CancelFunc
	secretRW   *secretRW
}

// kubeNamespace is a wrapper around namespace that helps to name things
// related to this namespace
type kubeNamespace string

func (n kubeNamespace) Bundle() workload.TrustedRootBundle {
	return workload.TrustedRootBundle{
		ID: n.BundleID(),
		CertAuthorityIDs: []string{
			n.CertAuthorityID(),
		},
	}
}

func (n kubeNamespace) SignPermissions() []workload.SignPermission {
	return []workload.SignPermission{
		{ID: n.ID(), CertAuthorityID: n.CertAuthorityID(), Org: n.CommonName(), MaxTTL: constants.DefaultMaxCertTTL},
	}
}

func (n kubeNamespace) Permissions() []workload.Permission {
	id := n.ID()
	return []workload.Permission{
		// authorities
		{ID: id, Action: workload.ActionReadPublic, Collection: workload.CollectionCertAuthorities},

		// workloads
		{ID: id, Action: workload.ActionRead, Collection: workload.CollectionWorkloads},

		// root bundles
		{ID: id, Action: workload.ActionRead, Collection: workload.CollectionTrustedRootBundles},
	}
}

func (n kubeNamespace) BundleID() string {
	return fmt.Sprintf("%v.svc.cluster.local", n)
}

func (n kubeNamespace) Org() string {
	return "svc.cluster.local"
}

func (n kubeNamespace) CommonName() string {
	return fmt.Sprintf("*.%v.svc.cluster.local", n)
}

func (n kubeNamespace) ID() identity.ID {
	return identity.MustParseID(fmt.Sprintf("urn:spiffe:%v", n.DomainName()))
}

func (n kubeNamespace) CertAuthorityID() string {
	return fmt.Sprintf("%v.svc.cluster.local", n)
}

func (n kubeNamespace) DomainName() string {
	return fmt.Sprintf("%v.svc.cluster.local", n)
}

func (n kubeNamespace) SecretID() string {
	return "spiffe-creds"
}

func convertError(err error) error {
	if err == nil {
		return nil
	}
	if errors.IsAlreadyExists(err) {
		return trace.AlreadyExists(err.Error())
	}
	if errors.IsNotFound(err) {
		return trace.NotFound(err.Error())
	}
	if errors.IsServerTimeout(err) {
		return trace.ConnectionProblem(err, err.Error())
	}
	if errors.IsUnauthorized(err) || errors.IsForbidden(err) {
		return trace.AccessDenied(err.Error())
	}
	return trace.BadParameter(err.Error())
}

type secretRW struct {
	namespace  string
	secretName string
	client     *kubernetes.Clientset
}

func (s *secretRW) DeleteKeyPair() error {
	err := s.client.Secrets(s.namespace).Delete(s.secretName, &api.DeleteOptions{})
	return convertError(err)
}

func (s *secretRW) ReadKeyPair() (*workload.KeyPair, error) {
	secret, err := s.client.Secrets(s.namespace).Get(s.secretName)
	if err != nil {
		return nil, convertError(err)
	}
	return &workload.KeyPair{CertPEM: secret.Data["cert"], KeyPEM: secret.Data["key"], CAPEM: secret.Data["ca-cert"]}, nil
}

func (s *secretRW) WriteKeyPair(keyPair workload.KeyPair) error {
	secret := v1.Secret{
		Data: map[string][]byte{
			"cert":    keyPair.CertPEM,
			"key":     keyPair.KeyPEM,
			"ca-cert": keyPair.CAPEM,
		},
	}
	secret.Name = s.secretName
	_, err := s.client.Secrets(s.namespace).Create(&secret)
	err = convertError(err)
	if err != nil {
		if !trace.IsAlreadyExists(err) {
			return trace.Wrap(err)
		}
	}
	_, err = s.client.Secrets(s.namespace).Update(&secret)
	return convertError(err)
}
