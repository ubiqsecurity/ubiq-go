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
	cache *bigcache.BigCache
}

func NewCache(ttl_seconds int) (cache, error) {
	ttlDuration := time.Duration(ttl_seconds) * time.Second
	Cache, err := bigcache.New(context.Background(), bigcache.DefaultConfig(ttlDuration))

	if err != nil {
		return cache{}, err
	}

	return cache{
		cache: Cache,
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
	if config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Storing key in cache %v \n", key)
	}
	v, err := json.Marshal(&value)

	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return kC.cache.Set(key, v)
}

func (kC *cache) readStructuredKey(key string) (structuredKey, error) {
	if config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Reading structured key from cache %v \n", key)
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
	if config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Storing dataset in cache %v \n", key)
	}
	v, err := json.Marshal(&value)

	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return kC.cache.Set(key, v)
}

func (kC *cache) readDataset(key string) (datasetInfo, error) {
	if config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Reading dataset from cache %v \n", key)
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
	if config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Storing unstructured key in cache %v \n", key)
	}
	v, err := json.Marshal(&value)

	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return dC.cache.Set(key, v)
}

func (dC *cache) readUnstructuredKey(key string) (decryptionKey, error) {
	if config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "Reading unstructured key from cache %v \n", key)
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

var ubiqCache cache
var config Configuration

func initializationCheck() error {
	var err error
	if config == (Configuration{}) {
		config, err = NewConfiguration()
		if err != nil {
			return err
		}
	}

	if config.KeyCaching.Structured && ubiqCache.cache == nil {
		ubiqCache, err = NewCache(config.KeyCaching.TTLSeconds)
		if err != nil {
			return err
		}
	}

	return nil
}
