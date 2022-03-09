// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/config"
	"go.etcd.io/bbolt"
)

var cacheImpl cache = nopCache{}

func InitCache(ctx context.Context) error {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return fmt.Errorf("failed to get configuration for cache: %w", err)
	}

	return InitCacheWithConf(ctx, conf.DiskCache)
}

func InitCacheWithConf(ctx context.Context, conf DiskCacheConf) error {
	if conf.Disabled {
		return nil
	}

	dc, err := newDiskCache(ctx, conf)
	if err != nil {
		return fmt.Errorf("failed to create compile disk cache: %w", err)
	}

	cacheImpl = dc
	return nil
}

var errKeyNotFound = errors.New("key not found")

type kind []byte

var (
	derivedRolesKind kind = []byte("dr")
	principalKind    kind = []byte("pp")
	resourceKind     kind = []byte("rp")
)

type vtproto interface {
	MarshalVT() ([]byte, error)
	UnmarshalVT([]byte) error
}

type cache interface {
	get([]byte, vtproto) error
	put([]byte, vtproto) error
}

// nopCache is the default placeholder that doesn't do anything
type nopCache struct{}

func (nc nopCache) get(_ []byte, _ vtproto) error {
	return errKeyNotFound
}

func (nc nopCache) put(_ []byte, _ vtproto) error {
	return nil
}

var _ cache = (*diskCache)(nil)

// diskCache maintains an on-disk cache of compiled artefacts
type diskCache struct {
	db *bbolt.DB
}

func newDiskCache(ctx context.Context, conf DiskCacheConf) (*diskCache, error) {
	dbFile := conf.Path
	if dbFile == "" {
		f, err := os.CreateTemp("", "cerbos_compile.cache*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary file for compile disk cache: %w", err)
		}

		dbFile = f.Name()
		_ = f.Close()
	}

	opts := &bbolt.Options{Timeout: 1 * time.Second, ReadOnly: conf.ReadOnly}
	db, err := bbolt.Open(dbFile, 0600, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache at %q: %w", dbFile, err)
	}

	go func() {
		<-ctx.Done()
		_ = db.Close()
	}()

	return &diskCache{db: db}, nil
}

func (dc *diskCache) get(key []byte, out vtproto) error {
	knd := getKind(out)
	return dc.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(knd)
		if b == nil {
			return fmt.Errorf("bucket %q not found", string(knd))
		}

		val := b.Get(key)
		if val == nil {
			return errKeyNotFound
		}

		return out.UnmarshalVT(val)
	})
}

func (dc *diskCache) put(key []byte, item vtproto) error {
	knd := getKind(item)
	return dc.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(knd)
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}

		itemBytes, err := item.MarshalVT()
		if err != nil {
			return fmt.Errorf("failed to marshal item: %w", err)
		}

		return b.Put(key, itemBytes)
	})
}

func getKind(item vtproto) kind {
	switch item.(type) {
	case *runtimev1.RunnableResourcePolicySet_Policy:
		return resourceKind
	case *runtimev1.RunnablePrincipalPolicySet_Policy:
		return principalKind
	case *runtimev1.RunnableDerivedRolesSet:
		return derivedRolesKind
	default:
		panic(fmt.Errorf("unknown item type: %T", item))
	}
}
