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

type ServiceConfig struct {
	Service workload.Service
}

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

type renewerBundle struct {
	renewer    *workload.CertRenewer
	cancelFunc context.CancelFunc
	secretRW   *secretRW
}

type Service struct {
	sync.Mutex
	client *kubernetes.Clientset
	ServiceConfig
	*log.Entry
	renewers map[string]*renewerBundle
}

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

func ReadKeyPairFromSecret(namespace string, name string) (*workload.KeyPair, error) {
	client, err := GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	secretRW := &secretRW{namespace: namespace, secretName: name, client: client}
	return secretRW.ReadKeyPair()
}

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

func (s *Service) deleteCertAuthority(ctx context.Context, namespace string) error {
	return s.Service.DeleteCertAuthority(ctx, IDForNamespace(namespace))
}

func (s *Service) deleteRenewer(ctx context.Context, namespace string) error {
	s.Lock()
	defer s.Unlock()
	r, ok := s.renewers[namespace]
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
	delete(s.renewers, namespace)
	return nil
}

func (s *Service) startRenewer(ctx context.Context, namespace string) error {
	s.Lock()
	defer s.Unlock()
	if _, ok := s.renewers[namespace]; ok {
		s.Infof("%v renewer already exists", namespace)
		return nil
	}
	s.Infof("creating new renewer %v", namespace)
	r, err := s.newRenewer(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	s.renewers[namespace] = r
	return nil
}

func (s *Service) installCertAuthority(ctx context.Context, namespace string) error {
	err := s.upsertCertAuthority(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.startRenewer(ctx, namespace)
	return trace.Wrap(err)
}

func (s *Service) uninstallCertAuthority(ctx context.Context, namespace string) error {
	err := s.deleteCertAuthority(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.deleteRenewer(ctx, namespace)
	return trace.Wrap(err)
}

func (s *Service) upsertCertAuthority(ctx context.Context, namespace string) error {
	s.Infof("upsertCertAuthority(namespace=%v)", namespace)
	_, err := s.Service.GetCertAuthorityCert(ctx, IDForNamespace(namespace))
	if err == nil {
		return nil
	}
	if !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	keyPEM, certPEM, err := identity.GenerateSelfSignedCA(pkix.Name{
		CommonName:   CommonNameForNamespace(namespace),
		Organization: []string{"svc.cluster.local"},
	}, nil, constants.DefaultCATTL)
	if err != nil {
		return trace.Wrap(err)
	}
	certAuthority := workload.CertAuthority{
		ID:         IDForNamespace(namespace),
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
		err = s.installCertAuthority(ctx, namespace.Name)
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
				if err := s.installCertAuthority(ctx, namespace); err != nil {
					return trace.Wrap(err)
				}
			}
			if event.Type == watch.Deleted {
				if err := s.uninstallCertAuthority(ctx, namespace); err != nil {
					return trace.Wrap(err)
				}
			}
		case <-ctx.Done():
			s.Infof("context is closing")
			return nil
		}
	}
}

func (s *Service) newRenewer(ctx context.Context, namespace string) (*renewerBundle, error) {
	renewerContext, cancelFunc := context.WithCancel(ctx)

	certAuthorityID := IDForNamespace(namespace)
	secretName := SecretIDForNamespace
	commonName := CommonNameForNamespace(namespace)
	spiffeID, err := identity.ParseID(fmt.Sprintf("urn:spiffe:%v", DomainNameForNamespace(namespace)))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	secretRW := &secretRW{
		client:     s.client,
		secretName: secretName,
		namespace:  namespace,
	}

	renewer, err := workload.NewCertRenewer(workload.CertRenewerConfig{
		Entry: log.WithFields(log.Fields{
			trace.Component: constants.ComponentSPIFFE,
		}),
		Template: workload.CertificateRequestTemplate{
			CertAuthorityID: certAuthorityID,
			ID:              *spiffeID,
			Subject: pkix.Name{
				CommonName: commonName,
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

func CommonNameForNamespace(namespace string) string {
	return fmt.Sprintf("*.%v.svc.cluster.local", namespace)
}

func IDForNamespace(namespace string) string {
	return fmt.Sprintf("%v.svc.cluster.local", namespace)
}

const SecretIDForNamespace = "spiffe-creds"

func DomainNameForNamespace(namespace string) string {
	return fmt.Sprintf("%v.svc.cluster.local", namespace)
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
