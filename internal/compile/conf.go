// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

const (
	confKey          = "compile"
	defaultCacheSize = 1024
)

// Conf is optional configuration for caches.
type Conf struct {
	// CacheSize is the number of compiled policies to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",example=1024"`
	// DiskCache configures the on-disk cache of compiled artefacts.
	DiskCache DiskCacheConf `yaml:"diskCache"`
}

type DiskCacheConf struct {
	// Disabled switches off the disk cache of compiled artefacts.
	Disabled bool `yaml:"disabled" conf:",example=false"`
	// ReadOnly marks the cache as read-only. Only one PDP can have read-write access to the cache.
	ReadOnly bool `yaml:"readOnly" conf:",example=false"`
	// Path sets the path to the cache file. Only one PDP can have read-write access to the file.
	Path string `yaml:"path" conf:",example=$TMP/cerbos_compile.cache"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.CacheSize = defaultCacheSize
}

// DefaultConf creates a config with defaults.
func DefaultConf() *Conf {
	cconf := &Conf{}
	cconf.SetDefaults()

	return cconf
}
