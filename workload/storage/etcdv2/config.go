/*
Copyright 2016 SPIFFE Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package etcdv2

import (
	"net"
	"net/http"
	"time"

	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/gravitational/trace"
)

const (
	// DefaultResponseTimeout specifies the default time limit to wait for response
	// header in a single request made by an etcd client
	DefaultResponseTimeout = 1 * time.Second

	// DefaultDialTimeout is default TCP connect timeout
	DefaultDialTimeout = 30 * time.Second

	// DefaultsReadHeadersTimeout is a default TCP timeout when we wait
	// for the response headers to arrive
	DefaultReadHeadersTimeout = 30 * time.Second

	// KeepaliveTimeout tells for how long keep the connection alive with no activity
	DefaultKeepAliveTimeout = 30 * time.Second

	// MaxIdleConnsPer host specifies the max amount of idle HTTP conns to keep
	DefaultMaxIdleConnsPerHost = 500
)

// Config defines the configuration to access etcd
type Config struct {
	// BackoffPeriod is a period between retries on failed API events
	// e.g. Watch on key
	BackoffPeriod time.Duration
	// Nodes lists etcd server endpoints (http://host:port)
	Nodes []string
	// Key is ETCD key prefix
	Key string
	// CAFile defines the SSL Certificate Authority file to used
	// to secure etcd communication
	TLSCAFile string
	// TLSCertFile defines the SSL certificate file to use to secure
	// etcd communication
	TLSCertFile string
	// TLSKeyFile defines the SSL key file to use to secure etcd communication
	TLSKeyFile string
	// HeaderTimeoutPerRequest specifies the time limit to wait for response
	// header in a single request made by a client
	HeaderTimeoutPerRequest time.Duration
	// DialTimeout is dial timeout
	DialTimeout time.Duration
	// DefaultsReadHeadersTimeout is a default TCP timeout when we wait
	// for the response headers to arrive
	ReadHeadersTimeout time.Duration
	// KeepaliveTimeout tells for how long keep the connection alive with no activity
	KeepAliveTimeout time.Duration
	// MaxIdleConnsPer host specifies the max amount of idle HTTP conns to keep
	MaxIdleConnsPerHost int
}

func (r *Config) CheckAndSetDefaults() error {
	if len(r.Nodes) == 0 {
		return trace.BadParameter("need at least one node")
	}
	if r.HeaderTimeoutPerRequest == 0 {
		r.HeaderTimeoutPerRequest = DefaultResponseTimeout
	}
	if r.DialTimeout == 0 {
		r.HeaderTimeoutPerRequest = DefaultResponseTimeout
	}
	if r.ReadHeadersTimeout == 0 {
		r.ReadHeadersTimeout = DefaultReadHeadersTimeout
	}
	if r.KeepAliveTimeout == 0 {
		r.KeepAliveTimeout = DefaultKeepAliveTimeout
	}
	if r.MaxIdleConnsPerHost == 0 {
		r.MaxIdleConnsPerHost = DefaultMaxIdleConnsPerHost
	}
	return nil
}

// NewClient creates a new instance of an etcd client
func (r *Config) NewClient() (etcd.Client, error) {
	info := transport.TLSInfo{
		CertFile: r.TLSCertFile,
		KeyFile:  r.TLSKeyFile,
		CAFile:   r.TLSCAFile,
	}
	tlsConfig, err := info.ClientConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: r.DialTimeout,
			// value taken from http.DefaultTransport
			KeepAlive: r.KeepAliveTimeout,
		}).Dial,
		// value taken from http.DefaultTransport
		TLSHandshakeTimeout: r.DialTimeout,
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: r.MaxIdleConnsPerHost,
	}
	client, err := etcd.New(etcd.Config{
		Endpoints:               r.Nodes,
		Transport:               transport,
		HeaderTimeoutPerRequest: r.HeaderTimeoutPerRequest,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return client, nil
}
