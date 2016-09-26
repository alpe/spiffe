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
// * Sets up TLS Certificate Authority for k8s cluster
// * Adds special identity that is authorized to sign certificates for this
// certificate authority (*.*.svc.cluster.local) matching subdomain
// assigned for this namespace
//
// * Creates (and mantains) secret in this namespace that contains certificate
//   and private key authenticated as SPIFFE identity assigned to the cluster
//   and certificate authority certificate to be trusted
//
package k8s

import (
	"crypto/x509/pkix"
	"fmt"
	"sync"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/errors"
	"k8s.io/client-go/1.4/pkg/api/v1"
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
	}, nil
}

// Service is K8s integration service. It is started in K8s mode
// and watches K8s namespaces setting up proper TLS infrastructure for them
type Service struct {
	sync.Mutex
	client *kubernetes.Clientset
	ServiceConfig
	*log.Entry
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
	secretRW, err := newSecretRW(secretRWConfig{
		namespace:  namespace,
		secretName: name,
		client:     client,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return secretRW.ReadKeyPair()
}

// Serve is a blocking call that launches the service
func (s *Service) Serve(ctx context.Context) error {
	err := s.installCertAuthority(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	<-ctx.Done()
	return nil
}

func (s *Service) installCertAuthority(ctx context.Context) error {
	s.Debugf("installCertAuthority")
	err := s.upsertCertAuthority(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.upsertPermissions(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.upsertBundle(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.startCertRenewer(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *Service) upsertBundle(ctx context.Context) error {
	s.Debugf("upsertBundle")
	err := s.Service.UpsertTrustedRootBundle(ctx, Bundle())
	return trace.Wrap(err)
}

func (s *Service) upsertPermissions(ctx context.Context) error {
	s.Debugf("upsertPermissions")
	for _, p := range Permissions() {
		if err := s.Service.UpsertPermission(ctx, p); err != nil {
			return trace.Wrap(err)
		}
	}

	for _, sp := range SignPermissions() {
		err := s.Service.UpsertSignPermission(ctx, sp)
		s.Debugf("upsertSignPermission %v, err: %v", sp, err)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (s *Service) upsertCertAuthority(ctx context.Context) error {
	s.Infof("upsertCertAuthority")
	_, err := s.Service.GetCertAuthorityCert(ctx, CertAuthorityID)
	if err == nil {
		return nil
	}
	if !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	keyPEM, certPEM, err := identity.GenerateSelfSignedCA(pkix.Name{
		CommonName:   CommonName,
		Organization: []string{Org},
	}, nil, constants.DefaultCATTL)
	if err != nil {
		return trace.Wrap(err)
	}
	certAuthority := workload.CertAuthority{
		ID:         CertAuthorityID,
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

func (s *Service) startCertRenewer(ctx context.Context) error {
	secretRW, err := newSecretRW(secretRWConfig{
		client:     s.client,
		secretName: SecretID,
		namespace:  SystemNamespace,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	renewer, err := workload.NewCertRenewer(workload.CertRenewerConfig{
		Entry: log.WithFields(log.Fields{
			trace.Component: constants.ComponentSPIFFE,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: constants.AdminOrg,
			ID:              SystemID(),
			Subject: pkix.Name{
				CommonName: CommonName,
			},
			TTL: constants.DefaultLocalCertTTL,
		},
		ReadKeyPair:  secretRW.ReadKeyPair,
		WriteKeyPair: secretRW.WriteKeyPair,
		Service:      s.Service,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	go func() {
		err := renewer.Start(ctx)
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()
	return nil
}

func Bundle() workload.TrustedRootBundle {
	return workload.TrustedRootBundle{
		ID: BundleID,
		CertAuthorityIDs: []string{
			CertAuthorityID,
		},
	}
}

// SignPermissions is a list of SignPermissions assigned to system ID
func SignPermissions() []workload.SignPermission {
	return []workload.SignPermission{
		{ID: SystemID(), CertAuthorityID: CertAuthorityID, MaxTTL: constants.DefaultMaxCertTTL},
	}
}

// Permissoins is a list of permissions assigned by system ID
func Permissions() []workload.Permission {
	id := SystemID()
	return []workload.Permission{
		// authorities
		{ID: id, Action: workload.ActionReadPublic, Collection: workload.CollectionCertAuthorities},

		// workloads
		{ID: id, Action: workload.ActionRead, Collection: workload.CollectionWorkloads},

		// root bundles
		{ID: id, Action: workload.ActionRead, Collection: workload.CollectionTrustedRootBundles},
	}
}

func SystemID() identity.ID {
	return identity.MustParseID(fmt.Sprintf("urn:spiffe:%v", DomainName))
}

const (
	// BundleID managed by this K8s integration
	BundleID = "svc.cluster.local"
	// CertAuthorityID is ID of the certificate authority managed by this K8s integration
	CertAuthorityID = "svc.cluster.local"
	// Org managed by K8s integration
	Org = "svc.cluster.local"
	// CommonName is a common name pattern allowed to be signed by K8s CA
	CommonName = "*.svc.cluster.local"
	// DomainName is a name of this Domain
	DomainName = "svc.cluster.local"
	// SecretID is ID of the secret generated
	SecretID = "spiffe-creds"
	// SystemNamespace is ID of the system namespace
	SystemNamespace = "SystemNamespace"
)

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

func newSecretRW(cfg secretRWConfig) (*secretRW, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &secretRW{
		secretRWConfig: cfg,
	}, nil
}

type secretRWConfig struct {
	namespace  string
	secretName string
	client     *kubernetes.Clientset
	keyName    string
	certName   string
	caName     string
}

func (s *secretRWConfig) CheckAndSetDefaults() error {
	if s.namespace == "" {
		return trace.BadParameter("missing parameter namespace")
	}
	if s.secretName == "" {
		return trace.BadParameter("missing parameter secretName")
	}
	if s.client == nil {
		return trace.BadParameter("missing parameter client")
	}
	if s.caName == "" {
		s.caName = constants.AdminCertCAFilename
	}
	if s.certName == "" {
		s.certName = constants.AdminCertFilename
	}
	if s.keyName == "" {
		s.keyName = constants.AdminKeyFilename
	}
	return nil
}

type secretRW struct {
	secretRWConfig
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
	return &workload.KeyPair{CertPEM: secret.Data[s.certName], KeyPEM: secret.Data[s.keyName], CAPEM: secret.Data["ca-cert"]}, nil
}

func (s *secretRW) WriteKeyPair(keyPair workload.KeyPair) error {
	secret := v1.Secret{
		Data: map[string][]byte{
			s.certName: keyPair.CertPEM,
			s.keyName:  keyPair.KeyPEM,
			s.caName:   keyPair.CAPEM,
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
