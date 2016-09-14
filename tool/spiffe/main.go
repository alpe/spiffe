package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spiffe/spiffe/process"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	if err := run(); err != nil {
		log.Error(trace.DebugReport(err))
		os.Exit(255)
	}
}

func run() error {
	var (
		app = kingpin.New("spiffe", "Starts SPIFFE certificate authority management service")

		configFile = app.Flag("config", "Path to config file").ExistingFile()
	)

	_, err := app.Parse(os.Args[1:])
	if err != nil {
		return trace.Wrap(err)
	}

	cfg, err := process.ConfigFromFile(*configFile)
	if err != nil {
		return trace.Wrap(err)
	}

	p, err := process.New(*cfg)
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

	return p.Start(ctx)
}
