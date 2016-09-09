where-am-i = $(CURDIR)/$(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))
SPIFFE_TEST_ETCD_CERTS := $(realpath $(dir $(call where-am-i))../fixtures/certs)
SPIFFE_TEST_ETCD_CONFIG := '{"Nodes": ["https://localhost:4001"], "Key":"/gravity/test", "TLSKeyFile": "$(SPIFFE_TEST_ETCD_CERTS)/proxy1-key.pem", "TLSCertFile": "$(SPIFFE_TEST_ETCD_CERTS)/proxy1.pem", "TLSCAFile": "$(SPIFFE_TEST_ETCD_CERTS)/ca.pem"}'
SPIFFE_TEST_ETCD_IMAGE := quay.io/coreos/etcd:v2.3.7
SPIFFE_TEST_ETCD_INSTANCE := testetcd0

.PHONY: base-etcd
base-etcd:
	if docker ps | grep $(SPIFFE_TEST_ETCD_INSTANCE) --quiet; then \
	  echo "ETCD is already running"; \
	else \
	  echo "starting test ETCD instance"; \
	  etcd_instance=$(shell docker ps -a | grep $(SPIFFE_TEST_ETCD_INSTANCE) | awk '{print $$1}'); \
	  if [ "$$etcd_instance" != "" ]; then \
	    docker rm -v $$etcd_instance; \
	  fi; \
	  docker run --net=host $(SPIFFE_TEST_ETCD_MOUNTS) --name=$(SPIFFE_TEST_ETCD_INSTANCE) -d -v $(SPIFFE_TEST_ETCD_CERTS):/certs $(SPIFFE_TEST_ETCD_IMAGE)  -name etcd0 -advertise-client-urls https://localhost:2379,https://localhost:4001  -listen-client-urls https://0.0.0.0:2379,https://0.0.0.0:4001  -initial-advertise-peer-urls https://localhost:2380  -listen-peer-urls https://0.0.0.0:2380  -initial-cluster-token etcd-cluster-1  -initial-cluster etcd0=https://localhost:2380  -initial-cluster-state new --cert-file=/certs/etcd1.pem --key-file=/certs/etcd1-key.pem --peer-cert-file=/certs/etcd1.pem --peer-key-file=/certs/etcd1-key.pem --peer-client-cert-auth --peer-trusted-ca-file=/certs/ca.pem -client-cert-auth --trusted-ca-file=/certs/ca.pem $(SPIFFE_TEST_ETCD_FLAGS) ; \
	fi;

.PHONY: test-etcd
test-etcd:
	$(MAKE) base-etcd
