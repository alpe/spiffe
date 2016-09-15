package spiffe

import (
	"os"
	"time"
)

const (
	// TestETCD is the name of the environment variable turning on/off Etcd tests
	TestETCD = "SPIFFE_TEST_ETCD"

	// TestETCDConfig is the name of test ETCD config environment variable
	TestETCDConfig = "SPIFFE_TEST_ETCD_CONFIG"

	// DefaultStateDir is a default state directory for local state
	DefaultStateDir = "/var/lib/spiffe"

	// ComponentSPIFFE is a name of the service
	ComponentSPIFFE = "spiffe"

	// DefaultConfigFileName is a default config file name
	DefaultConfigFileName = "spiffe.yaml"

	// AdminOrg is the name of the amdin org used locally inside cluster
	AdminOrg = "spiffe.localhost.localdomain"

	// AdminID is ID of the local SID generated locally by the service
	AdminID = "urn:spiffe:spiffe.localhost.localdomain:admin"

	// DefaultRSABits is the default RSA bits for the private key
	DefaultRSABits = 2048

	// DefaultCATTL is a default lifetime of a CA certificate
	DefaultCATTL = time.Hour * 24 * 365 * 10

	// DefaultLocalCertTTL is a default lifetime of a local certificate
	DefaultLocalCertTTL = 10 * time.Hour

	// DefalutPrivateFileMask is for private non executable files
	DefaultPrivateFileMask os.FileMode = 0600
)
