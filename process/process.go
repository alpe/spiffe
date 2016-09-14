package process

import (
	"net/http"
	_ "net/http/pprof"

	"github.com/spiffe/spiffe"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
)

func New(config Config) (*Process, error) {
	if err := config.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	if config.Debug {
		spiffe.InitLoggerDebug()
	} else {
		spiffe.InitLoggerCLI()
	}
	return &Process{
		Config: config,
		Entry:  log.WithFields(log.Fields{trace.Component: spiffe.ComponentSPIFFE}),
	}, nil
}

type Process struct {
	Config
	*log.Entry
}

func (p *Process) Start(ctx context.Context) error {
	prettyConfig, _ := yaml.Marshal(p.Config)
	p.Infof("starting with config: %v", string(prettyConfig))

	if p.ProfileListenAddr != "" {
		p.Infof("starting HTTP profile endpoint on %v", p.ProfileListenAddr)
		go func() {
			err := http.ListenAndServe(p.ProfileListenAddr, nil)
			if err != nil {
				log.Error(trace.DebugReport(err))
			}
		}()
	}

	select {
	case <-ctx.Done():
		p.Infof("context closed, exiting")
		return nil
	}
}
