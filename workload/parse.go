package workload

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
)

// ParseCertificateRequestPEM parses PEM-encoded certificate signing request
func ParseCertificateRequestPEM(bytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, trace.BadParameter("expected PEM-encoded block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, trace.BadParameter(err.Error())
	}
	return csr, nil
}

// ParseCertificatePEM parses PEM-encoded certificate
func ParseCertificatePEM(bytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, trace.BadParameter("expected PEM-encoded block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, trace.BadParameter(err.Error())
	}
	return cert, nil
}

// ParsePrivateKeyPEM parses PEM-encoded private key
func ParsePrivateKeyPEM(bytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, trace.BadParameter("expected PEM-encoded block")
	}
	return ParsePrivateKeyDER(block.Bytes)
}

// ParsePrivateKeyDER parses unencrypted DER-encoded private key
func ParsePrivateKeyDER(der []byte) (crypto.Signer, error) {
	generalKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		generalKey, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			generalKey, err = x509.ParseECPrivateKey(der)
			if err != nil {
				log.Errorf("failed to parse key: %v", err)
				return nil, trace.BadParameter("failed parsing private key")
			}
		}
	}

	switch generalKey.(type) {
	case *rsa.PrivateKey:
		return generalKey.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		return generalKey.(*ecdsa.PrivateKey), nil
	}

	return nil, trace.BadParameter("unsupported private key type")
}
