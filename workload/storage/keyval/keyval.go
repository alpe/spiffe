package keyval

import (
	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
)

func New(cfg Config) (*Backend, error) {
	libkv.NewStore()
}

type Config struct {
	Type    store.Backend
	Addrs   []string
	Options *store.Config
}

func NewStore(backend store.Backend, addrs []string, options *store.Config) (store.Store, error) {

}
