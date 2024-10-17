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
