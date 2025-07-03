package ubiq

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/allegro/bigcache/v3"
)

var (
	ErrNotInCache = errors.New("key is not in cache")
)

type cache struct {
	cache  *bigcache.BigCache
	config *Configuration
}

func NewCache(cfg *Configuration) (cache, error) {
	ttlDuration := time.Duration(cfg.KeyCaching.TTLSeconds) * time.Second

	if cfg.Golang.CacheShards <= 0 || (cfg.Golang.CacheShards & (cfg.Golang.CacheShards - 1)) != 0 {
		return cache{}, fmt.Errorf("configuration error - cache_shards must be a power of 2 and greater than 0 (current value: %v)", cfg.Golang.CacheShards)
	}

	// Modify the default configuration (Fully custom leaves some uninitialized)
	CacheConfig := bigcache.DefaultConfig(ttlDuration)

	CacheConfig.HardMaxCacheSize = cfg.Golang.CacheHardMaxSizeMB

	CacheConfig.Shards = cfg.Golang.CacheShards
	// If less than 0, cache will never evict.
	CacheConfig.CleanWindow = time.Duration(cfg.Golang.CacheCleanWindowS)
	CacheConfig.Verbose = cfg.Logging.Verbose
	CacheConfig.MaxEntriesInWindow = cfg.Golang.CacheMaxEntriesInWindow

	Cache, err := bigcache.New(context.Background(), CacheConfig)

	if err != nil {
		return cache{}, err
	}

	return cache{
		cache:  Cache,
		config: cfg,
	}, err
}

func getStructuredCacheKey(papi, name string, n int) string {
	return fmt.Sprintf("%s-%s-%v", papi, name, n)
}

func getStructuredDatasetKey(papi, name string) string {
	return fmt.Sprintf("%s-%s", papi, name)
}

func getUnstructuredCacheKey(edk []byte, algo int) string {
	edk_base64 := base64.StdEncoding.EncodeToString(edk)
	return fmt.Sprintf("%s-%v", edk_base64, algo)
}

func (kC *cache) updateStructuredKey(key string, value structuredKey) error {
	if kC.config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Storing key in cache %.10s... \n", key)
	}
	v, err := json.Marshal(&value)

	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return kC.cache.Set(key, v)
}

func (kC *cache) readStructuredKey(key string) (structuredKey, error) {
	if kC.config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Reading structured key from cache %.10s... \n", key)
	}
	v, err := kC.cache.Get(key)
	if err != nil {
		if errors.Is(err, bigcache.ErrEntryNotFound) {
			return structuredKey{}, ErrNotInCache
		}
		return structuredKey{}, fmt.Errorf("get Key error: %w", err)
	}

	var stKey structuredKey
	err = json.Unmarshal(v, &stKey)
	if err != nil {
		return structuredKey{}, fmt.Errorf("unmarshal: %w", err)
	}
	return stKey, err
}

func (kC *cache) updateDataset(key string, value datasetInfo) error {
	if kC.config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Storing dataset in cache %.10s... \n", key)
	}
	v, err := json.Marshal(&value)

	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return kC.cache.Set(key, v)
}

func (kC *cache) readDataset(key string) (datasetInfo, error) {
	if kC.config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Reading dataset from cache %.10s... \n", key)
	}
	v, err := kC.cache.Get(key)
	if err != nil {
		if errors.Is(err, bigcache.ErrEntryNotFound) {
			return datasetInfo{}, ErrNotInCache
		}
		return datasetInfo{}, fmt.Errorf("Get Key Error: %w", err)
	}

	var dataset datasetInfo
	err = json.Unmarshal(v, &dataset)
	if err != nil {
		return datasetInfo{}, fmt.Errorf("unmarshal: %w", err)
	}

	return dataset, err
}

func (dC *cache) updateUnstructuredKey(key string, value decryptionKey) error {
	if dC.config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Storing unstructured key in cache %.10s... \n", key)
	}
	v, err := json.Marshal(&value)

	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return dC.cache.Set(key, v)
}

func (dC *cache) readUnstructuredKey(key string) (decryptionKey, error) {
	if dC.config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Reading unstructured key from cache \n")
	}
	v, err := dC.cache.Get(key)
	if err != nil {
		if errors.Is(err, bigcache.ErrEntryNotFound) {
			return decryptionKey{}, ErrNotInCache
		}
		return decryptionKey{}, fmt.Errorf("get Key error: %w", err)
	}

	var decryptKey decryptionKey
	err = json.Unmarshal(v, &decryptKey)
	if err != nil {
		return decryptionKey{}, fmt.Errorf("unmarshal: %w", err)
	}
	return decryptKey, err
}

func initializeCache(cfg *Configuration) (ubiqCache cache, err error) {
	if cfg.KeyCaching.Structured && ubiqCache.cache == nil {
		return NewCache(cfg)
	}

	return ubiqCache, err
}
