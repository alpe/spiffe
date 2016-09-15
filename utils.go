package spiffe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log/syslog"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	logrusSyslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/gravitational/trace"
)

// InitLoggerCLI tools by default log into syslog, not stderr
func InitLoggerCLI() {
	log.SetLevel(log.WarnLevel)
	// clear existing hooks:
	log.StandardLogger().Hooks = make(log.LevelHooks)
	log.SetFormatter(&trace.TextFormatter{})

	hook, err := logrusSyslog.NewSyslogHook("", "", syslog.LOG_WARNING, "")
	if err != nil {
		// syslog not available
		log.Warn("syslog not available. reverting to stderr")
	} else {
		// ... and disable stderr:
		log.AddHook(hook)
		log.SetOutput(ioutil.Discard)
	}
}

// InitLoggerDebug configures the logger to dump everything to stderr
func InitLoggerDebug() {
	// clear existing hooks:
	log.StandardLogger().Hooks = make(log.LevelHooks)
	log.SetFormatter(&trace.TextFormatter{})
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
}

// GenerateRSAPrivateKeyPEM generates new RSA private key and returns PEM encoded bytes
func GenerateRSAPrivateKeyPEM() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, DefaultRSABits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), nil
}

// GenerateSelfSignedCA generates self-signed certificate authority used for internal inter-node communications
func GenerateSelfSignedCA(entity pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, DefaultRSABits)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(ttl)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Issuer:                entity,
		Subject:               entity,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:     true,
		DNSNames: dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	return keyPEM, certPEM, nil
}

// GetFreeTCPPorts returns a lit of available ports on localhost
// used for testing
func GetFreeTCPPorts(n int) ([]string, error) {
	list := make([]string, 0, n)
	for i := 0; i < n; i++ {
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			return nil, trace.Wrap(err)
		}
		listener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		defer listener.Close()
		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			return nil, trace.BadParameter("Can't get tcp address")
		}
		list = append(list, strconv.Itoa(tcpAddr.Port))
	}
	return list, nil
}

// SetupTLS sets up some modern suites, preference, and min TLS versions
func SetupTLS(config *tls.Config) {
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,

		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}

	config.MinVersion = tls.VersionTLS12
	config.SessionTicketsDisabled = false
	config.ClientSessionCache = tls.NewLRUClientSessionCache(
		1024)
}
