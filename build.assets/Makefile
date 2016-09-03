PROTOC_VER ?= 3.0.0
GOGO_PROTO_TAG ?= 5f813990bfffa3c2f4414dbea480e705ab280358
GRPC_GATEWAY_TAG ?= c8ec92d0481dd77d9b8c1808eb6476d190aa039a
BUILDBOX_TAG := spifee-buildbox:0.0.1
PLATFORM := linux-x86_64
PROTO_DIR ?= 

# buildbox builds docker buildbox image used to compile binaries and generate GRPc stuff
.PHONY: buildbox
buildbox:
	docker build \
          --build-arg PROTOC_VER=$(PROTOC_VER) \
          --build-arg=GOGO_PROTO_TAG=$(GOGO_PROTO_TAG) \
          --build-arg GRPC_GATEWAY_TAG=$(GRPC_GATEWAY_TAG) \
          --build-arg PLATFORM=$(PLATFORM) \
          -t $(BUILDBOX_TAG) .

# proto generates probuf stuff inside buildbox
.PHONY: proto
proto:
# standard GRPC output
	cd $(PROTO_DIR) && protoc -I=.:$$PROTO_INCLUDE \
      --go_out=.=plugins=grpc,import_prefix=github.com/spiffe/:.\
    *.proto
# HTTP JSON gateway adapter
	cd $(PROTO_DIR) && protoc -I=.:$$PROTO_INCLUDE \
      --grpc-gateway_out=logtostderr=true:. \
      --swagger_out=logtostderr=true:. \
      *.proto	
