/*
Copyright 2016 SPIFFE authors

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

package process

import (
	"path/filepath"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/identity"
	"github.com/spiffe/spiffe/lib/toolbox"
	"github.com/spiffe/spiffe/lib/workload/storage/etcdv2"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Debug             bool
	StateDir          string
	K8s               K8s
	ProfileListenAddr string
	RPCListenAddr     string
	AdvertiseHostname string
	Backend           BackendConfig
	ServerID          string
}

type K8s struct {
	Enabled bool
}

type BackendConfig struct {
	Type   string
	EtcdV2 etcdv2.Config
}

const (
	BackendTypeEtcdV2 = "etcdv2"
)

func (cfg *Config) Check() error {
	if cfg.ServerID == "" {
		return trace.BadParameter("missing parameter ServerID")
	}
	if _, err := identity.ParseID(cfg.ServerID); err != nil {
		return trace.Wrap(err)
	}
	if cfg.RPCListenAddr == "" {
		return trace.BadParameter("missing RPCListenAddr")
	}
	if cfg.AdvertiseHostname == "" {
		return trace.BadParameter("missing AdvertiseHostname")
	}
	if cfg.Backend.Type != BackendTypeEtcdV2 {
		return trace.BadParameter("unsupported backend: %v", cfg.Backend.Type)
	}
	if err := cfg.Backend.EtcdV2.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func ConfigFromFile(fileName string) (*Config, error) {
	if fileName == "" {
		fileName = filepath.Join(constants.DefaultStateDir, constants.DefaultConfigFileName)
	}

	log.Debugf("look up config in %v", fileName)

	data, err := toolbox.ReadPath(fileName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := cfg.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &cfg, nil
}
