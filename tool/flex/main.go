package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/local/localapi"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
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

		debug      = app.Flag("debug", "turn on debug logging").Bool()
		socketPath = app.Flag("socket", "path to unix socket").Default(constants.DefaultUnixSocketPath).String()

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

	conn, err := grpc.Dial("localhost:0", grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, _ time.Duration) (net.Conn, error) {
			return net.Dial("unix", *socketPath)
		}))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	client, err := localapi.NewClient(conn)
	if err != nil {
		return nil, trace.Wrap(err)
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
