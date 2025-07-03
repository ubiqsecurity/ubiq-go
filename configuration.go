package ubiq

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
)

type Configuration struct {
	EventReporting struct {
		WakeInterval         int    `json:"wake_interval"`
		MinimumCount         int    `json:"minimum_count"`
		FlushInterval        int    `json:"flush_interval"`
		TrapExceptions       bool   `json:"trap_exceptions"`
		TimestampGranularity string `json:"timestamp_granularity"`
	} `json:"event_reporting"`

	Logging struct {
		Verbose bool `json:"verbose"`
	} `json:"logging"`

	KeyCaching struct {
		Unstructured bool `json:"unstructured"`
		Structured   bool `json:"structured"`
		Encrypt      bool `json:"encrypt"`
		TTLSeconds   int  `json:"ttl_seconds"`
	} `json:"key_caching"`

	Idp struct {
		Provider         string `json:"provider"`
		CustomerId       string `json:"ubiq_customer_id"`
		TokenEndpointUrl string `json:"idp_token_endpoint_url"`
		TenantId         string `json:"idp_tenant_id"`
		ClientSecret     string `json:"idp_client_secret"`
	} `json:"idp"`

	Golang struct {
		// Size in MB
		CacheHardMaxSizeMB int `json:"cache_hard_max_size_mb"`
		// In Seconds
		CacheCleanWindowS int `json:"cache_clean_window_s"`
		// # of Shards
		CacheShards int `json:"cache_shards"`
		// # of Entries
		CacheMaxEntriesInWindow int `json:"cache_max_entries_in_window"`
		// Cache math is MaxEntriesInWindow * MaxEntrySize (500)
		// This changes if you have enough shards that Entries/Shards < 10
		// then it's Shards * 10 * MaxEntrySize
	} `json:"golang"`
}

func (config *Configuration) setDefaults() {
	config.EventReporting.WakeInterval = 10
	config.EventReporting.MinimumCount = 50
	config.EventReporting.FlushInterval = 90
	config.EventReporting.TrapExceptions = false
	config.EventReporting.TimestampGranularity = "MICROS"

	config.Logging.Verbose = false

	config.KeyCaching.Structured = true
	config.KeyCaching.Unstructured = true
	config.KeyCaching.Encrypt = false
	config.KeyCaching.TTLSeconds = 1800

	config.Idp.Provider = ""
	config.Idp.CustomerId = ""
	config.Idp.TokenEndpointUrl = ""
	config.Idp.TenantId = ""
	config.Idp.ClientSecret = ""

	config.Golang.CacheHardMaxSizeMB = 0
	config.Golang.CacheCleanWindowS = 1
	config.Golang.CacheShards = 1024
	config.Golang.CacheMaxEntriesInWindow = 1000 * 10 * 60
}

func NewConfiguration(args ...string) (Configuration, error) {
	config := Configuration{}
	config.setDefaults()

	var err error
	var path string

	if len(args) > 0 {
		path = args[0]
	} else {
		var u *user.User
		u, _ = user.Current()
		path = filepath.Join(u.HomeDir, ".ubiq", "configuration")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, (fs.ErrNotExist)) {
			return config, nil
		}
	}

	err = json.Unmarshal(content, &config)

	return config, err
}

func NewConfigurationFromJson(jsonConfig string) (Configuration, error) {
	config := Configuration{}
	config.setDefaults()

	err := json.Unmarshal([]byte(jsonConfig), &config)

	return config, err
}
