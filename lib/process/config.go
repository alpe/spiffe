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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/workload/storage/etcdv2"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Debug             bool
	StateDir          string
	ProfileListenAddr string
	AdvertiseHostname string
	Backend           BackendConfig
}

type BackendConfig struct {
	Type   string
	EtcdV2 etcdv2.Config
}

const (
	BackendTypeEtcdV2 = "etcdv2"
)

func (cfg *Config) Check() error {
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

func NormalizePath(path string) (string, error) {
	s, err := filepath.Abs(path)
	if err != nil {
		return "", trace.ConvertSystemError(err)
	}
	abs, err := filepath.EvalSymlinks(s)
	if err != nil {
		return "", trace.ConvertSystemError(err)
	}
	return abs, nil
}

func WritePath(path string, data []byte, perm os.FileMode) error {
	err := ioutil.WriteFile(path, data, perm)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	return nil
}

func ReadPath(path string) ([]byte, error) {
	abs, err := NormalizePath(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	bytes, err := ioutil.ReadFile(abs)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return bytes, nil
}

func ConfigFromFile(fileName string) (*Config, error) {
	if fileName == "" {
		fileName = filepath.Join(constants.DefaultStateDir, constants.DefaultConfigFileName)
	}

	log.Debugf("look up config in %v", fileName)

	data, err := ReadPath(fileName)
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
