package main

import (
	"github.com/spiffe/spiffe/lib/workload"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
)

func attach(ctx context.Context, service workload.Service, args string) (interface{}, error) {
	log.Infof("attach(%v)", args)
	return &attachResponse{Status: StatusSuccess, Device: "/dev/fake"}, nil
}

func detach(ctx context.Context, service workload.Service, args string) (interface{}, error) {
	log.Infof("detach(%v)", args)
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

func mount(ctx context.Context, service workload.Service, mountPath, device, args string) (interface{}, error) {
	log.Infof("mount(%v, %v, %v)", mountPath, device, args)
	return &statusResponse{Status: StatusSuccess, Message: "all is well"}, nil
}

func unmount(ctx context.Context, service workload.Service, args string) (interface{}, error) {
	log.Infof("unmount(%v)", args)
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
