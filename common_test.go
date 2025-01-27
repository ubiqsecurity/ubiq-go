package ubiq

var credentials Credentials
var initialized bool

// Each new instance of Credentials costs 330MB
// This creates a singleton in order to allow reuse across tests, to reduce memory bloat.
// When you call creds.Close() it does free it **just not in tests**
// Tested (thorougly) on 01/16/2024
func initializeCreds() {
	if !initialized {
		credentials, _ = NewCredentials()
		initialized = true
	}
}
