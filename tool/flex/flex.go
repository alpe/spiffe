package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/local"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

const (
	typeBundle = "bundle"
	typeCert   = "cert"
)

const (
	DefaultBundleID        = "kube-system.svc.cluster.local"
	DefaultCertAuthorityID = "kube-system.svc.cluster.local"
	DefaultCommonName      = "*.kube-system.svc.cluster.local"
	DefaultID              = "urn:spiffe:svc.cluster.local:generic"
)

type rawRequest struct {
	Type              string `json:"type"`
	CommonName        string `json:"commonName"`
	TTL               string `json:"ttl"`
	BundleID          string `json:"bundleID"`
	Key               string `json:"key" yaml:"key"`
	Cert              string `json:"cert" yaml:"cert"`
	CertAuthorityCert string `json:"certAuthorityCert"`
	CertAuthorityID   string `json:"certAuthorityID"`
	Identity          string `json:"identity"`
}

type request struct {
	certReq   *local.CertRequest
	bundleReq *local.BundleRequest
}

func initFlex(ctx context.Context, service local.Renewer, args string) (interface{}, error) {
	log.Infof("init(%v)", args)
	return &statusResponse{Status: StatusSuccess, Message: "init done"}, nil
}

func attach(ctx context.Context, service local.Renewer, args string) (interface{}, error) {
	log.Infof("attach(%v)", args)
	return &attachResponse{Status: StatusSuccess, Device: "/dev/fake"}, nil
}

func detach(ctx context.Context, service local.Renewer, args string) (interface{}, error) {
	log.Infof("detach(%v)", args)
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

func mount(ctx context.Context, service local.Renewer, mountPath, device, args string) (interface{}, error) {
	log.Infof("mount(%v, %v, %v)", mountPath, device, args)
	err := os.MkdirAll(mountPath, constants.DefaultSharedDirMask)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req, err := parseRequest(mountPath, args)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if req.bundleReq != nil {
		if err := service.CreateBundleRequest(ctx, *req.bundleReq); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if req.certReq != nil {
		if err := service.CreateCertRequest(ctx, *req.certReq); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

func unmount(ctx context.Context, service local.Renewer, dir string) (interface{}, error) {
	log.Errorf("unmount(%v)", dir)
	err := service.DeleteBundleRequest(ctx, dir)
	if err != nil {
		if err := service.DeleteCertRequest(ctx, dir); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	err = os.RemoveAll(dir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

func parseRequest(dir string, data string) (*request, error) {
	var raw rawRequest
	err := json.Unmarshal([]byte(data), &raw)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch raw.Type {
	case typeBundle:
		req := &local.BundleRequest{
			ID:        dir,
			BundleID:  raw.BundleID,
			TargetDir: dir,
		}
		if req.BundleID == "" {
			req.BundleID = DefaultBundleID
		}
		return &request{bundleReq: req}, nil
	case typeCert:
		var ttl time.Duration
		if raw.TTL == "" {
			ttl = constants.DefaultLocalCertTTL
		} else {
			if ttl, err = time.ParseDuration(raw.TTL); err != nil {
				return nil, trace.Wrap(err)
			}
		}
		if raw.CertAuthorityID == "" {
			raw.CertAuthorityID = DefaultCertAuthorityID
		}
		if raw.CommonName == "" {
			raw.CommonName = DefaultCommonName
		}
		if raw.Key == "" {
			raw.Key = "private.pem"
		}
		if raw.Cert == "" {
			raw.Cert = "cert.pem"
		}
		if raw.CertAuthorityCert == "" {
			raw.CertAuthorityCert = "ca-cert.pem"
		}
		if raw.Identity == "" {
			raw.Identity = DefaultID
		}
		id, err := identity.ParseID(raw.Identity)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		req := &local.CertRequest{
			ID:              dir,
			CertAuthorityID: raw.CertAuthorityID,
			CommonName:      raw.CommonName,
			Identity:        *id,
			TTL:             ttl,
			KeyPath:         filepath.Join(dir, raw.Key),
			CertPath:        filepath.Join(dir, raw.Cert),
			CAPath:          filepath.Join(dir, raw.CertAuthorityCert),
		}
		return &request{certReq: req}, nil
	default:
		return nil, trace.BadParameter("unsupported request type: %v", raw.Type)
	}

}

const (
	StatusSuccess = "Success"
	StatusFailure = "Failure"
)

type statusResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type attachResponse struct {
	Status string `json:"status"`
	Device string `json:"device"`
}
