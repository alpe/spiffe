package process

import (
	"io/ioutil"
	"path/filepath"

	"github.com/spiffe/spiffe"
	"github.com/spiffe/spiffe/workload/storage/etcdv2"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Debug             bool
	StateDir          string
	ProfileListenAddr string
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
	if cfg.Backend.Type != BackendTypeEtcdV2 {
		return trace.BadParameter("unsupported backend: %v", cfg.Backend.Type)
	}
	if err := cfg.Backend.EtcdV2.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func ReadPath(path string) ([]byte, error) {
	s, err := filepath.Abs(path)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	abs, err := filepath.EvalSymlinks(s)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	bytes, err := ioutil.ReadFile(abs)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return bytes, nil
}

func ConfigFromFile(fileName string) (*Config, error) {
	if fileName == "" {
		fileName = filepath.Join(spiffe.DefaultStateDir, spiffe.DefaultConfigFileName)
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
