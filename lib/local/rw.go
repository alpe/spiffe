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

package local

import (
	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/toolbox"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
)

// CertReadWriter implements local filesystem reader writer of keypairs and certificates
// issued by certificate authorities
type CertReadWriter struct {
	CertReadWriterConfig
}

func NewCertReadWriter(cfg CertReadWriterConfig) (*CertReadWriter, error) {
	if err := cfg.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &CertReadWriter{
		CertReadWriterConfig: cfg,
	}, nil
}

type CertReadWriterConfig struct {
	KeyPath  string
	CertPath string
	CAPath   string
}

func (c *CertReadWriterConfig) Check() error {
	if c.KeyPath == "" {
		return trace.BadParameter("missing parameter KeyPath")
	}
	if c.CertPath == "" {
		return trace.BadParameter("missing parameter CertPath")
	}
	return nil
}

func (l *CertReadWriter) ReadKeyPair() (*workload.KeyPair, error) {
	keyData, err := toolbox.ReadPath(l.KeyPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if _, err := workload.ParsePrivateKeyPEM(keyData); err != nil {
		log.Debugf("failed to parse %v key, will overwrite", l.KeyPath)
		return nil, trace.NotFound("ignoring bad key")
	}
	certData, err := toolbox.ReadPath(l.CertPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if _, err := workload.ParseCertificatePEM(certData); err != nil {
		log.Debugf("failed to parse %v cert, will overwrite", l.CertPath)
		return nil, trace.NotFound("ignoring bad certificate")
	}
	return &workload.KeyPair{KeyPEM: keyData, CertPEM: certData}, nil
}

func (l *CertReadWriter) WriteKeyPair(keyPair workload.KeyPair) error {
	if err := toolbox.WritePath(l.KeyPath, keyPair.KeyPEM, constants.DefaultPrivateFileMask); err != nil {
		return trace.Wrap(err)
	}
	if err := toolbox.WritePath(l.CertPath, keyPair.CertPEM, constants.DefaultPrivateFileMask); err != nil {
		return trace.Wrap(err)
	}
	if l.CAPath != "" {
		if err := toolbox.WritePath(l.CAPath, keyPair.CAPEM, constants.DefaultPrivateFileMask); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}
