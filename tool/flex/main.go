package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	//	"path/filepath"
	"strings"
	"syscall"

	//	"github.com/spiffe/spiffe/lib/constants"
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
	response, err := run()
	if err != nil {
		log.Error(trace.DebugReport(err))
		response = statusResponse{
			Status:  StatusFailure,
			Message: err.Error(),
		}
	}
	fmt.Print(marshal(response))
}

func marshal(in interface{}) string {
	out, err := json.Marshal(in)
	if err != nil {
		log.Error(trace.DebugReport(err))
		return `{"Status": "Failure", "Message": "failed to marshal response"}`
	}
	return string(out)
}

const flexDir = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/spiffe.io~spiffe"

func run() (interface{}, error) {
	var (
		app = kingpin.New("flex", "Flex volume plugin for K8s")

		debug = app.Flag("debug", "turn on debug logging").Bool()
		//targetAddr = app.Flag("server", "hostport of the target spiffe server").Default("spiffe.kube-system.svc.cluster.local:3443").String()
		//certPath   = app.Flag("cert-file", "path to client certificate file").Default(filepath.Join(flexDir, constants.AdminCertFilename)).String()
		//keyPath    = app.Flag("key-file", "path to client private key file").Default(filepath.Join(flexDir, constants.AdminKeyFilename)).String()
		//caPath     = app.Flag("ca-file", "path to client certificate authority cert file").Default(filepath.Join(flexDir, constants.AdminCertCAFilename)).String()

		cinit     = app.Command("init", "init")
		cinitArgs = cinit.Arg("args", "init arguments").String()

		cattach     = app.Command("attach", "attach volume")
		cattachArgs = cattach.Arg("args", "attach arguments").String()

		cdetach     = app.Command("detach", "detach volume")
		cdetachArgs = cdetach.Arg("args", "detach arguments").String()

		cmount       = app.Command("mount", "mount args")
		cmountPath   = cmount.Arg("path", "mount path").String()
		cmountDevice = cmount.Arg("device", "mount device").String()
		cmountArgs   = cmount.Arg("args", "mount device").String()

		cunmount    = app.Command("unmount", "unmount args")
		cunmountDir = cunmount.Arg("dir", "unmount directrory").String()
	)

	cmd, err := app.Parse(os.Args[1:])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if *debug {
		identity.InitLoggerDebug()
	} else {
		identity.InitLoggerCLI()
	}

	/*
		keyPair, err := getCreds(*certPath, *keyPath, *caPath, "", "")
		if err != nil {
			return nil, trace.Wrap(err)
		}
	*/

	var client *api.Client
	/*
		client, err := api.NewClientFromConfig(api.ClientConfig{
			TLSKey:     keyPair.KeyPEM,
			TLSCert:    keyPair.CertPEM,
			TLSCA:      keyPair.CAPEM,
			TargetAddr: *targetAddr,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}*/

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
	case cinit.FullCommand():
		return initFlex(ctx, client, *cinitArgs)
	case cattach.FullCommand():
		return attach(ctx, client, *cattachArgs)
	case cattach.FullCommand():
		return attach(ctx, client, *cattachArgs)
	case cdetach.FullCommand():
		return detach(ctx, client, *cdetachArgs)
	case cmount.FullCommand():
		return mount(ctx, client, *cmountPath, *cmountDevice, *cmountArgs)
	case cunmount.FullCommand():
		return unmount(ctx, client, *cunmountDir)
	}

	return nil, trace.BadParameter("unsupported command: %v", cmd)
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
