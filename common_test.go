package ubiq

import "os"

var credentials Credentials
var initialized bool

// Each new instance of Credentials costs 330MB
// This creates a singleton in order to allow reuse across tests, to reduce memory bloat.
// When you call creds.Close() it does free it **just not in tests**
// Tested (thorougly) on 01/16/2024
//
// Set UBIQ_TEST_PROFILE to use a specific credentials profile (e.g. "dev", "prod").
// Defaults to the default profile if not set.
func initializeCreds() {
	if !initialized {
		profile := os.Getenv("UBIQ_TEST_PROFILE")
		if profile != "" {
			credentials, _ = NewCredentials("", profile)
		} else {
			credentials, _ = NewCredentials()
		}
		initialized = true
	}
}
