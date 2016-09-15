PROTOC_VER ?= 3.0.0
GOGO_PROTO_TAG ?= v0.3
GRPC_GATEWAY_TAG ?= v1.1.0
BUILDBOX_TAG := spifee-buildbox:0.0.1
PLATFORM := linux-x86_64
GRPC_DIRS := workload/api

include build.assets/etcd.mk


# all goinstalls everything
.PHONY: all
all: install

# install installs binary
.PHONY: install
install: 
	go install github.com/spiffe/spiffe/tool/spiffe github.com/spiffe/spiffe/tool/spiffectl

# run runs local dev server
.PHONY: run
run: install test-etcd
	spiffe --config=./fixtures/local.yaml

.PHONY: test

test: test-etcd remove-temp-files
	SPIFFE_TEST_ETCD=true SPIFFE_TEST_ETCD_CONFIG=$(SPIFFE_TEST_ETCD_CONFIG) go test -v -test.parallel=0 . ./workload/...

test-package: test-etcd remove-temp-files
	SPIFFE_TEST_ETCD=true SPIFFE_TEST_ETCD_CONFIG=$(SPIFFE_TEST_ETCD_CONFIG) go test -v ./$(p) -check.f=$(e)

cover-package: test-etcd remove-temp-files
	SPIFFE_TEST_ETCD=true SPIFFE_TEST_ETCD_CONFIG=$(SPIFFE_TEST_ETCD_CONFIG) go test -v ./$(p)  -coverprofile=/tmp/coverage.out
	go tool cover -html=/tmp/coverage.out


# send sends test message
.PHONY: send
send: install
	spiffectl "hola, SPIFFE"

# buildbox builds docker buildbox image used to compile binaries and generate GRPc stuff
.PHONY: buildbox
buildbox:
	cd build.assets && docker build \
          --build-arg PROTOC_VER=$(PROTOC_VER) \
          --build-arg GOGO_PROTO_TAG=$(GOGO_PROTO_TAG) \
          --build-arg GRPC_GATEWAY_TAG=$(GRPC_GATEWAY_TAG) \
          --build-arg PLATFORM=$(PLATFORM) \
          -t $(BUILDBOX_TAG) .

# proto generates GRPC defs from service definitions
.PHONY: grpc
grpc: buildbox
	docker run -v $(shell pwd):/go/src/github.com/spiffe/spiffe $(BUILDBOX_TAG) make -C /go/src/github.com/spiffe/spiffe buildbox-grpc

# proto generates GRPC stuff inside buildbox
.PHONY: buildbox-grpc
buildbox-grpc:
# standard GRPC output
	echo $$PROTO_INCLUDE
	cd $(GRPC_DIRS) && protoc -I=.:$$PROTO_INCLUDE \
      --gofast_out=plugins=grpc:.\
    *.proto
# HTTP JSON gateway adapter
	cd $(GRPC_DIRS) && protoc -I=.:$$PROTO_INCLUDE \
      --grpc-gateway_out=logtostderr=true:. \
      --swagger_out=logtostderr=true:. \
      *.proto	


# This is to clean up flymake_ stuff hanging around as a result of Emacs-Flymake
.PHONY: remove-temp-files
remove-temp-files:
	@if [ $$USER != vagrant ] ; then \
		find . -name flymake_* -delete ; \
	fi


PWD := $(shell pwd)
REPODIR ?= $(abspath $(PWD))
SRCDIR := /go/src/github.com/spiffe/spiffe

#
# Runs tests inside a build container
#
.PHONY: test-docker
test-docker: buildbox test-etcd
	docker run --net=host --rm=true -u $$(id -u) -v $(REPODIR):$(SRCDIR) -t $(BUILDBOX_TAG) \
		/bin/bash -c "cd $(SRCDIR) && make buildbox-test"


.PHONY: buildbox-test
buildbox-test:
	SPIFFE_TEST_ETCD=true SPIFFE_TEST_ETCD_CONFIG=$(SPIFFE_TEST_ETCD_CONFIG) go test -v -test.parallel=0 -cover -race . ./workload/...
