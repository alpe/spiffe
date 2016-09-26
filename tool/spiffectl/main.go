package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/k8s"
	"github.com/spiffe/spiffe/lib/toolbox"
	"github.com/spiffe/spiffe/lib/workload"
	"github.com/spiffe/spiffe/lib/workload/api"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	identity.InitLoggerCLI()
	if err := run(); err != nil {
		log.Error(trace.DebugReport(err))
		fmt.Printf("ERROR: %v\n", err.Error())
		os.Exit(255)
	}
}

func run() error {
	var (
		app = kingpin.New("spiffectl", "CLI utility to talk to SPIFFE service")

		debug      = app.Flag("debug", "turn on debug logging").Bool()
		targetAddr = app.Flag("server", "hostport of the target spiffe server").Default("localhost:3443").String()
		certPath   = app.Flag("cert-file", "path to client certificate file").Default(filepath.Join(constants.DefaultStateDir, constants.AdminCertFilename)).String()
		keyPath    = app.Flag("key-file", "path to client private key file").Default(filepath.Join(constants.DefaultStateDir, constants.AdminKeyFilename)).String()
		caPath     = app.Flag("ca-file", "path to client certificate authority cert file").Default(filepath.Join(constants.DefaultStateDir, constants.AdminCertCAFilename)).String()

		k8sSecretNamespace = app.Flag("k8s-namespace", "namespace").Default("default").String()
		k8sSecretName      = app.Flag("k8s-secret", "name of kubernetes secret to pull credentials from").String()

		cbundles     = app.Command("bundle", "operations on trusted root certificate bundles")
		cbundlesList = cbundles.Command("ls", "list trusted root certificate bundles")

		cbundlesCreate        = cbundles.Command("create", "create trusted root certificate bundles")
		cbundlesCreateReplace = cbundlesCreate.Flag("replace", "replace bundle if it exists").Bool()
		cbundlesCreateID      = cbundlesCreate.Flag("id", "unique bundle id").Required().String()
		cbundlesCreateDirs    = cbundlesCreate.Flag("dir", "import certificates from directory").Strings()
		cbundlesCreateCAIDs   = cbundlesCreate.Flag("ca", "use existing certificate authority id").Strings()

		cbundlesExport      = cbundles.Command("export", "export trusted root bundle to directory")
		cbundlesExportWatch = cbundlesExport.Flag("watch", "watch and update bundle's directory if bundle gets updated").Bool()
		cbundlesExportID    = cbundlesExport.Flag("id", "unique bundle id").Required().String()
		cbundlesExportDir   = cbundlesExport.Flag("dir", "target directory [WARNING] all directory content's will be removed").Required().String()
		cbundlesExportHooks = cbundlesExport.Flag("exec", "optional command to execute when bundle updates").Strings()

		cbundlesDelete   = cbundles.Command("rm", "remove bundle")
		cbundlesDeleteID = cbundlesDelete.Flag("id", "unique bundle id").Required().String()

		cca = app.Command("ca", "operations on certificate authorities")

		ccaList = cca.Command("ls", "list certificate authorities")

		ccaCreate           = cca.Command("create", "create new certificate authority (CA)")
		ccaCreateReplace    = ccaCreate.Flag("replace", "replace CA if it exists").Bool()
		ccaCreateID         = ccaCreate.Flag("id", "unique CA id").Required().String()
		ccaCreateCommonName = ccaCreate.Flag("common-name", "CA common name").Required().String()
		ccaCreateOrg        = ccaCreate.Flag("org", "CA org name").Required().String()
		ccaCreateTTL        = ccaCreate.Flag("ttl", "CA TTL").Required().Duration()

		ccaImport         = cca.Command("import", "import certificate authority (CA) from existing keypair")
		ccaImportReplace  = ccaImport.Flag("replace", "replace CA if it exists").Bool()
		ccaImportID       = ccaImport.Flag("id", "unique CA id").Required().String()
		ccaImportKeyPath  = ccaImport.Flag("in-key-file", "path to existing key file").Required().ExistingFile()
		ccaImportCertPath = ccaImport.Flag("in-cert-file", "path to existing cert file").Required().String()

		ccaSign                = cca.Command("sign", "create and sign keypair using certificate authority ID")
		ccaSignRenew           = ccaSign.Flag("renew", "block and renew certificate authority periodically").Bool()
		ccaSignTTL             = ccaSign.Flag("ttl", "TTL for the certificate").Required().Duration()
		ccaSignCommonName      = ccaSign.Flag("common-name", "certificate common name to issue").Required().String()
		ccaSignID              = ID(ccaSign.Flag("id", "SPIFFE ID to embed in the certificate").Required())
		ccaSignCertAuthorityID = ccaSign.Flag("ca", "CA id to sign this certificate with").Required().String()
		ccaSignKeyPath         = ccaSign.Flag("out-key-file", "path to write key file").Required().String()
		ccaSignCertPath        = ccaSign.Flag("out-cert-file", "path to write cert file").Required().String()
		ccaSignCACertPath      = ccaSign.Flag("out-ca-cert-file", "path to write CA cert file").String()
		ccaSignHooks           = ccaSign.Flag("exec", "optional command to execute when bundle updates").Strings()

		ccaDelete   = cca.Command("rm", "remove certificate authority")
		ccaDeleteID = ccaDelete.Flag("id", "unique CA id").Required().String()

		cnode           = app.Command("node", "start node local service")
		cnodeStatePath  = cnode.Flag("state", "path to database with state").Default(filepath.Join(constants.DefaultStateDir, constants.DefaultLocalDBName)).String()
		cnodeSocketPath = cnode.Flag("socket", "path to unix socket").Default(constants.DefaultUnixSocketPath).String()
	)

	cmd, err := app.Parse(os.Args[1:])
	if err != nil {
		return trace.Wrap(err)
	}

	if *debug {
		identity.InitLoggerDebug()
	}

	keyPair, err := getCreds(*certPath, *keyPath, *caPath, *k8sSecretNamespace, *k8sSecretName)
	if err != nil {
		return trace.Wrap(err)
	}

	client, err := api.NewClientFromConfig(api.ClientConfig{
		TLSKey:     keyPair.KeyPEM,
		TLSCert:    keyPair.CertPEM,
		TLSCA:      keyPair.CAPEM,
		TargetAddr: *targetAddr,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		exitSignals := make(chan os.Signal, 1)
		signal.Notify(exitSignals, syscall.SIGTERM, syscall.SIGINT)

		select {
		case sig := <-exitSignals:
			log.Infof("signal: %v", sig)
			cancel()
		}
	}()

	switch cmd {
	case cnode.FullCommand():
		return nodeServe(ctx, client, *cnodeStatePath, *cnodeSocketPath)
	case cbundlesList.FullCommand():
		return bundlesList(ctx, client)
	case cbundlesCreate.FullCommand():
		return bundleCreate(ctx, client, *cbundlesCreateID, *cbundlesCreateDirs, *cbundlesCreateCAIDs, *cbundlesCreateReplace)
	case cbundlesDelete.FullCommand():
		return bundleDelete(ctx, client, *cbundlesDeleteID)
	case cbundlesExport.FullCommand():
		return bundleExport(ctx, client, *cbundlesExportID, *cbundlesExportDir, *cbundlesExportWatch, *cbundlesExportHooks)
	case ccaList.FullCommand():
		return certAuthoritiesList(ctx, client)
	case ccaCreate.FullCommand():
		return certAuthorityGenerate(ctx, client, *ccaCreateID, *ccaCreateCommonName, *ccaCreateOrg, *ccaCreateTTL, *ccaCreateReplace)
	case ccaImport.FullCommand():
		return certAuthorityImport(ctx, client, *ccaImportID, *ccaImportKeyPath, *ccaImportCertPath, *ccaImportReplace)
	case ccaSign.FullCommand():
		return certAuthoritySign(ctx, client, ccaSignID.ID(), *ccaSignCertAuthorityID, *ccaSignKeyPath, *ccaSignCertPath, *ccaSignCACertPath, *ccaSignCommonName, *ccaSignTTL, *ccaSignRenew, *ccaSignHooks)
	case ccaDelete.FullCommand():
		return certAuthorityDelete(ctx, client, *ccaDeleteID)
	}

	return trace.BadParameter("unsupported command: %v", cmd)
}

func printHeader(val string) {
	fmt.Printf("\n[%v]\n%v\n", val, strings.Repeat("-", len(val)+2))
}

func ID(s kingpin.Settings) *spiffeID {
	id := new(spiffeID)
	s.SetValue(id)
	return id
}

type spiffeID identity.ID

func (id *spiffeID) ID() identity.ID {
	return (identity.ID)(*id)
}

func (id *spiffeID) Set(val string) error {
	out, err := identity.ParseID(val)
	if err != nil {
		return trace.Wrap(err)
	}
	*id = spiffeID(*out)
	return nil
}

func (id *spiffeID) String() string {
	return (*identity.ID)(id).String()
}

func getCreds(certPath, keyPath, caPath, k8sNamespace, k8sSecret string) (*workload.KeyPair, error) {
	if k8sSecret != "" {
		log.Debugf("pulling creds from secret %v in %v namespace", k8sSecret, k8sNamespace)
		return k8s.ReadKeyPairFromSecret(k8sNamespace, k8sSecret)
	}
	log.Debugf("pulling creds from local paths cert=%v key=%v ca-cert=%v", certPath, keyPath, caPath)

	certPEM, err := toolbox.ReadPath(certPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	keyPEM, err := toolbox.ReadPath(keyPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	caPEM, err := toolbox.ReadPath(caPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &workload.KeyPair{CertPEM: certPEM, KeyPEM: keyPEM, CAPEM: caPEM}, nil
}
