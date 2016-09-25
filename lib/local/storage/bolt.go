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

package storage

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spiffe/spiffe/lib/constants"
	"github.com/spiffe/spiffe/lib/local"
	"github.com/spiffe/spiffe/lib/toolbox"

	log "github.com/Sirupsen/logrus"
	"github.com/boltdb/bolt"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"
)

// Config is a BoltDB backend configuration
type Config struct {
	// Codec is used to encode and decode values from the storage
	Codec Codec `json:"-"`
	// Path is a path to DB file
	Path string `json:"path" yaml:"path"`
	// Readonly sets bolt to read only mode
	Readonly bool `json:"readonly" yaml:"readonly"`
	// OpenTimeout sets database open timeout
	OpenTimeout time.Duration `json:"openTimeout" yaml:"openTimeout"`
	// FileMask sets file mask
	FileMask os.FileMode `json:"fileMask" yaml:"fileMask"`
}

func (b *Config) CheckAndSetDefaults() error {
	if b.Codec == nil {
		b.Codec = &JSONCodec{}
	}
	if b.Path == "" {
		return trace.BadParameter("missing Path parameter")
	}
	path, err := filepath.Abs(b.Path)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	b.Path = path
	if _, err := toolbox.StatDir(filepath.Dir(b.Path)); err != nil {
		return trace.Wrap(err)
	}
	if b.OpenTimeout == 0 {
		b.OpenTimeout = constants.DefaultDialTimeout
	}
	if b.FileMask == 0 {
		b.FileMask = constants.DefaultPrivateFileMask
	}
	return nil
}

// New returns new BoltDB-backed engine
func New(cfg Config) (*Bolt, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	b := &Bolt{
		Config: cfg,
	}

	options := &bolt.Options{Timeout: cfg.OpenTimeout, ReadOnly: false}
	db, err := bolt.Open(cfg.Path, cfg.FileMask, options)
	if err != nil {
		if err == bolt.ErrTimeout {
			return nil, trace.ConnectionProblem(
				nil, "local storage at %v is locked. Another instance is running?", cfg.Path)
		}
		return nil, trace.Wrap(err)
	}
	b.db = db
	if !cfg.Readonly {
		log.Infof("BOLT: locked %v", b.Path)
	}
	return b, nil
}

// Bolt is a BoltDB-backend engine
type Bolt struct {
	sync.Mutex
	Config
	db *bolt.DB
}

func upsertBucket(tx *bolt.Tx, buckets []string) (*bolt.Bucket, error) {
	bkt, err := tx.CreateBucketIfNotExists([]byte(buckets[0]))
	if err != nil {
		return nil, trace.Wrap(boltErr(err))
	}
	for _, key := range buckets[1:] {
		bkt, err = bkt.CreateBucketIfNotExists([]byte(key))
		if err != nil {
			return nil, trace.Wrap(boltErr(err))
		}
	}
	return bkt, nil
}

func createBucket(tx *bolt.Tx, buckets []string) (*bolt.Bucket, error) {
	bkt, err := tx.CreateBucketIfNotExists([]byte(buckets[0]))
	if err != nil {
		return nil, trace.Wrap(boltErr(err))
	}
	rest := buckets[1:]
	for i, key := range rest {
		if i == len(rest)-1 {
			bkt, err = bkt.CreateBucket([]byte(key))
			if err != nil {
				return nil, trace.Wrap(boltErr(err))
			}
		} else {
			bkt, err = bkt.CreateBucketIfNotExists([]byte(key))
			if err != nil {
				return nil, trace.Wrap(boltErr(err))
			}
		}
	}
	return bkt, nil
}

func getBucket(tx *bolt.Tx, buckets []string) (*bolt.Bucket, error) {
	bkt := tx.Bucket([]byte(buckets[0]))
	if bkt == nil {
		return nil, trace.NotFound("bucket %v not found", buckets[0])
	}
	for _, key := range buckets[1:] {
		bkt = bkt.Bucket([]byte(key))
		if bkt == nil {
			return nil, trace.NotFound("bucket %v not found", key)
		}
	}
	return bkt, nil
}

var (
	bundlesBucket = []string{"bundles"}
	certsBucket   = []string{"certs"}
)

func (b *Bolt) CreateBundleRequest(ctx context.Context, req local.BundleRequest) error {
	encoded, err := b.Codec.EncodeToBytes(req)
	if err != nil {
		return trace.Wrap(err)
	}
	key := req.LocalID()
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt, err := upsertBucket(tx, bundlesBucket)
		if err != nil {
			return trace.Wrap(err)
		}
		val := bkt.Get([]byte(key))
		if val != nil {
			return trace.AlreadyExists("'%v' already exists", key)
		}
		return bkt.Put([]byte(key), encoded)
	})
}

func (b *Bolt) CreateCertRequest(ctx context.Context, req local.CertRequest) error {
	encoded, err := b.Codec.EncodeToBytes(req)
	if err != nil {
		return trace.Wrap(err)
	}
	key := req.LocalID()
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt, err := upsertBucket(tx, certsBucket)
		if err != nil {
			return trace.Wrap(err)
		}
		val := bkt.Get([]byte(key))
		if val != nil {
			return trace.AlreadyExists("'%v' already exists", key)
		}
		return bkt.Put([]byte(key), encoded)
	})
}

func (b *Bolt) DeleteBundleRequest(ctx context.Context, targetDir string) error {
	id := local.LocalBundleRequestID(targetDir)
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt, err := getBucket(tx, bundlesBucket)
		if err != nil {
			return trace.Wrap(err)
		}
		if bkt.Get([]byte(id)) == nil {
			return trace.NotFound("%v is not found", id)
		}
		return bkt.Delete([]byte(id))
	})
}

func (b *Bolt) DeleteCertRequest(ctx context.Context, certPath string) error {
	id := local.LocalCertRequestID(certPath)
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt, err := getBucket(tx, certsBucket)
		if err != nil {
			return trace.Wrap(err)
		}
		if bkt.Get([]byte(id)) == nil {
			return trace.NotFound("%v is not found", id)
		}
		return bkt.Delete([]byte(id))
	})
}

func (b *Bolt) GetBundleRequests(ctx context.Context) ([]local.BundleRequest, error) {
	out := []local.BundleRequest{}
	err := b.db.View(func(tx *bolt.Tx) error {
		bkt, err := getBucket(tx, bundlesBucket)
		if err != nil {
			if trace.IsNotFound(err) {
				return nil
			}
			return trace.Wrap(err)
		}
		c := bkt.Cursor()
		var req local.BundleRequest
		for k, val := c.First(); k != nil; k, val = c.Next() {
			err := b.Codec.DecodeFromBytes(val, &req)
			if err != nil {
				return trace.Wrap(boltErr(err))
			}
			out = append(out, req)
		}
		return nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return out, nil
}

func (b *Bolt) GetCertRequests(ctx context.Context) ([]local.CertRequest, error) {
	out := []local.CertRequest{}
	err := b.db.View(func(tx *bolt.Tx) error {
		bkt, err := getBucket(tx, certsBucket)
		if err != nil {
			if trace.IsNotFound(err) {
				return nil
			}
			return trace.Wrap(err)
		}
		c := bkt.Cursor()
		var req local.CertRequest
		for k, val := c.First(); k != nil; k, val = c.Next() {
			err := b.Codec.DecodeFromBytes(val, &req)
			if err != nil {
				return trace.Wrap(boltErr(err))
			}
			out = append(out, req)
		}
		return nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return out, nil
}

// Close closes the backend resources
func (b *Bolt) Close() error {
	log.Infof("BOLT closing: %v", b.Path)
	return b.db.Close()
}

func boltErr(err error) error {
	if err == bolt.ErrBucketNotFound {
		return trace.NotFound(err.Error())
	}
	if err == bolt.ErrBucketExists {
		return trace.AlreadyExists(err.Error())
	}
	return err
}
