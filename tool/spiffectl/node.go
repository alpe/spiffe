package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spiffe/spiffe/lib/local"
	"github.com/spiffe/spiffe/lib/local/localapi"
	"github.com/spiffe/spiffe/lib/local/storage/bolt"
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func nodeServe(ctx context.Context, service workload.Service, statePath, socketPath string) error {
	backend, err := bolt.New(bolt.Config{
		Path: statePath,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	renewerService, err := local.New(local.Config{
		Workload: service,
		Storage:  backend,
	})

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return trace.Wrap(err)
	}
	defer os.Remove(socketPath)
	defer listener.Close()

	renewerServer, err := localapi.NewServer(renewerService)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := renewerService.Serve(ctx); err != nil {
		return trace.Wrap(err)
	}

	server := grpc.NewServer()
	localapi.RegisterRenewerServer(server, renewerServer)

	go func() {
		err := server.Serve(listener)
		if err != nil {
			log.Error(trace.DebugReport(err))
		}
	}()

	fmt.Printf("now listening on %v\n", socketPath)

	<-ctx.Done()
	return nil
}
