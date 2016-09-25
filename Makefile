PROTOC_VER ?= 3.0.0
GOGO_PROTO_TAG ?= v0.3
GRPC_GATEWAY_TAG ?= v1.1.0
BUILDBOX_TAG := spifee-buildbox:0.0.1
PLATFORM := linux-x86_64
GRPC_WORKLOAD := lib/workload/api
GRPC_LOCAL := lib/local/localapi
BUILDDIR ?= .
IMAGE := spiffe
TAG := 0.0.1

include build.assets/etcd.mk


# all goinstalls everything
.PHONY: all
all: install

# version prints current version
.PHONY: version
version:
	echo $(TAG)

# install installs binary
.PHONY: install
install: 
	go install github.com/spiffe/spiffe/tool/spiffe github.com/spiffe/spiffe/tool/spiffectl github.com/spiffe/spiffe/tool/flex

.PHONY: build
build:
	go build -o $(BUILDDIR)/spiffe github.com/spiffe/spiffe/tool/spiffe
	go build -o $(BUILDDIR)/spiffectl github.com/spiffe/spiffe/tool/spiffectl
	go build -o $(BUILDDIR)/flex github.com/spiffe/spiffe/tool/flex

# run runs local dev server
.PHONY: run
run: install test-etcd
	spiffe --config=./fixtures/local.yaml

.PHONY: test

test: test-etcd remove-temp-files
	SPIFFE_TEST_ETCD=true SPIFFE_TEST_ETCD_CONFIG=$(SPIFFE_TEST_ETCD_CONFIG) go test -v -test.parallel=0 ./lib/...

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


# containers builds container with spiffe
.PHONY: containers
containers:
	$(eval TMPDIR := $(shell mktemp -d))
	if [ ! -d "$(TMPDIR)" ] ; then \
		echo "failed to generate temp dir" && exit 255 ;\
	fi
	mkdir -p $(TMPDIR)/build/opt/spiffe
	docker run -v $(shell pwd):/go/src/github.com/spiffe/spiffe -v $(TMPDIR)/build/opt/spiffe:/out $(BUILDBOX_TAG) make -C /go/src/github.com/spiffe/spiffe build BUILDDIR=/out
	cp build.assets/k8s/docker/spiffe.dockerfile $(TMPDIR)
	cp build.assets/install-flex.sh $(TMPDIR)/build/opt/spiffe
	chmod +x $(TMPDIR)/build/opt/spiffe/install-flex.sh
	cd $(TMPDIR) && docker build -t $(IMAGE):$(TAG) --file spiffe.dockerfile .
	rm -rf $(TMPDIR)

.PHONY: dev-containers
dev-containers: containers
	docker tag $(IMAGE):$(TAG) apiserver:5000/$(IMAGE):latest
	docker tag $(SPIFFE_TEST_ETCD_IMAGE) apiserver:5000/$(SPIFFE_TEST_ETCD_IMAGE)
	docker push apiserver:5000/$(IMAGE):latest
	docker push apiserver:5000/$(SPIFFE_TEST_ETCD_IMAGE)


.PHONY: dev-create
dev-create: dev-spiffe-create

.PHONY: dev-spiffe-create
dev-spiffe-create:
	kubectl create -f build.assets/k8s/resources/etcd-secrets.yaml
	kubectl create -f build.assets/k8s/resources/spiffe.yaml

.PHONY: dev-nginx-create
dev-nginx-create:
	kubectl create -f build.assets/k8s/resources/nginx.yaml

.PHONY: dev-nginx-destroy
dev-nginx-destroy:
	- kubectl --namespace=kube-system delete services/nginx
	- kubectl --namespace=kube-system delete deployments/nginx
	- kubectl --namespace=kube-system delete configmaps/nginx

.PHONY: dev-spiffe-destroy
dev-spiffe-destroy:
	- kubectl --namespace=kube-system delete daemonsets/spiffe-node
	- kubectl --namespace=kube-system delete deployments/spiffe
	- kubectl --namespace=kube-system delete configmaps/etcd-secrets
	- kubectl --namespace=kube-system delete configmaps/spiffe
	- kubectl --namespace=kube-system delete services/spiffe

.PHONY: dev-destroy
dev-destroy: dev-spiffe-destroy

.PHONY: dev-redeploy
dev-redeploy: dev-destroy dev-containers dev-create

# proto generates GRPC defs from service definitions
.PHONY: grpc
grpc: buildbox
	docker run -v $(shell pwd):/go/src/github.com/spiffe/spiffe $(BUILDBOX_TAG) make -C /go/src/github.com/spiffe/spiffe buildbox-grpc

# proto generates GRPC stuff inside buildbox
.PHONY: buildbox-grpc
buildbox-grpc:
# standard GRPC output
	echo $$PROTO_INCLUDE
	cd $(GRPC_WORKLOAD) && protoc -I=.:$$PROTO_INCLUDE \
      --gofast_out=plugins=grpc:.\
    *.proto
# HTTP JSON gateway adapter
	cd $(GRPC_WORKLOAD) && protoc -I=.:$$PROTO_INCLUDE \
      --grpc-gateway_out=logtostderr=true:. \
      --swagger_out=logtostderr=true:. \
      *.proto

# standard GRPC output
	echo $$PROTO_INCLUDE
	cd $(GRPC_LOCAL) && protoc -I=.:$$PROTO_INCLUDE \
      --gofast_out=plugins=grpc:.\
    *.proto
# HTTP JSON gateway adapter
	cd $(GRPC_LOCAL) && protoc -I=.:$$PROTO_INCLUDE \
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
	SPIFFE_TEST_ETCD=true SPIFFE_TEST_ETCD_CONFIG=$(SPIFFE_TEST_ETCD_CONFIG) go test -v -test.parallel=0 -cover ./lib/...
