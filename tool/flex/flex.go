package main

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

func initFlex(ctx context.Context, service workload.Service, args string) (interface{}, error) {
	log.Errorf("init(%v)", args)
	return &statusResponse{Status: StatusSuccess, Message: "init done"}, nil
}

func attach(ctx context.Context, service workload.Service, args string) (interface{}, error) {
	log.Errorf("attach(%v)", args)
	return &attachResponse{Status: StatusSuccess, Device: "/dev/fake"}, nil
}

func detach(ctx context.Context, service workload.Service, args string) (interface{}, error) {
	log.Errorf("detach(%v)", args)
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

func mount(ctx context.Context, service workload.Service, mountPath, device, args string) (interface{}, error) {
	log.Errorf("mount(%v, %v, %v)", mountPath, device, args)
	err := os.MkdirAll(mountPath, 755)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	err = ioutil.WriteFile(filepath.Join(mountPath, "flex.dat"), []byte("flex baby 2"), 0644)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

func unmount(ctx context.Context, service workload.Service, dir string) (interface{}, error) {
	log.Errorf("unmount(%v)", dir)
	err := os.RemoveAll(dir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

const (
	StatusSuccess = "Success"
	StatusFailure = "Failure"
)

type statusResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type attachResponse struct {
	Status string `json:"status"`
	Device string `json:"device"`
}
