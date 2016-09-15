package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/process"
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
		targetAddr = app.Flag("server", "Hostport of the target spiffe server").Default("localhost:3443").String()
		certPath   = app.Flag("cert-file", "Path to client certificate file").Default(filepath.Join(constants.DefaultStateDir, constants.AdminCertFilename)).ExistingFile()
		keyPath    = app.Flag("key-file", "Path to client private key file").Default(filepath.Join(constants.DefaultStateDir, constants.AdminKeyFilename)).ExistingFile()
		caPath     = app.Flag("ca-file", "Path to client certificate authority cert file").Default(filepath.Join(constants.DefaultStateDir, constants.AdminCertCAFilename)).ExistingFile()
	)

	_, err := app.Parse(os.Args[1:])
	if err != nil {
		return trace.Wrap(err)
	}

	if *debug {
		identity.InitLoggerDebug()
	}

	certPEM, err := process.ReadPath(*certPath)
	if err != nil {
		return trace.Wrap(err)
	}

	keyPEM, err := process.ReadPath(*keyPath)
	if err != nil {
		return trace.Wrap(err)
	}

	caPEM, err := process.ReadPath(*caPath)
	if err != nil {
		return trace.Wrap(err)
	}

	client, err := api.NewClientFromConfig(api.ClientConfig{
		TLSKey:     keyPEM,
		TLSCert:    certPEM,
		TLSCA:      caPEM,
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

	out, err := client.GetCertAuthority(ctx, constants.AdminOrg)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("* %v\n", out.ID)
	return nil
}
