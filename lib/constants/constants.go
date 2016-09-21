/*
Copyright 2016 SPIFFE authors

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

package constants

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

	// ComponentCLI is a name of the CLI tool
	ComponentCLI = "spiffectl"

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

	// DefaultMaxCertTTL is a default maximum TTL of issued certificate (1 year)
	DefaultMaxCertTTL = time.Hour * 24 * 365

	// DefaultLocalCertTTL is a default lifetime of a local certificate
	DefaultLocalCertTTL = 10 * time.Hour

	// DefaultSharedFileMask is for shared non executable files
	DefaultSharedFileMask os.FileMode = 0644

	// DefalutPrivateFileMask is for private non executable files
	DefaultPrivateFileMask os.FileMode = 0600

	// DefalutPrivateDirMask is for private directories
	DefaultPrivateDirMask os.FileMode = 0700

	// AdminKeyFilename is a filename of admin's certificate private key
	AdminKeyFilename = "admin.pem"
	// AdminCertFilename is a filename of admin's certificate
	AdminCertFilename = "admin.cert"
	// AdminCertFilename is a filename of certificate authority signed the cert
	AdminCertCAFilename = "admin-ca.cert"

	// DefaultDialTimeout sets default timeout for dialing some RPC endpoint
	DefaultDialTimeout = 30 * time.Second

	// DefaultReconnectPeriod is a default period for various reconnect attempts
	DefaultReconnectPeriod = 5 * time.Second
)
