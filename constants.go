package spiffe

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
)
