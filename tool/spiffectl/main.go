package main

import (
	"os"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"

	log "github.com/Sirupsen/logrus"
	gw "github.com/spiffe/spiffe/workload/workloadpb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	address     = "localhost:9090"
	defaultName = "world"
)

type passCredential int

func (passCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Basic admin",
	}, nil
}

func (passCredential) RequireTransportSecurity() bool {
	return false
}

func main() {
	// Set up a connection to the server.
	var cred passCredential
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithPerRPCCredentials(cred))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := gw.NewYourServiceClient(conn)

	// Contact the server and print out its response.
	message := defaultName
	if len(os.Args) > 1 {
		message = os.Args[1]
	}
	var header metadata.MD
	r, err := c.Echo(context.Background(), &gw.StringMessage{Value: message}, grpc.Header(&header))
	if err != nil {
		err = trail.FromGRPC(err, header)
		log.Errorf("error saying echo: %v", trace.DebugReport(err))
		return
	}
	log.Infof("Response: %s", r.Value)
}
