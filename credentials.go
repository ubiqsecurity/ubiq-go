package ubiq

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/go-ini/ini"
)

const (
	credentialsPapiId = "ACCESS_KEY_ID"
	credentialsSapiId = "SECRET_SIGNING_KEY"
	credentialsSrsaId = "SECRET_CRYPTO_ACCESS_KEY"
	credentialsHostId = "SERVER"

	credentialsPapiEnvId = "UBIQ_" + credentialsPapiId
	credentialsSapiEnvId = "UBIQ_" + credentialsSapiId
	credentialsSrsaEnvId = "UBIQ_" + credentialsSrsaId
	credentialsHostEnvId = "UBIQ_" + credentialsHostId

	credentialsDefaultProfileId = "default"
	credentialsDefaultHost      = "api.ubiqsecurity.com"
)

// Credentials holds the caller's credentials which are used
// to authenticate the caller to the Ubiq platform. Credentials
// must always be created/initialized via the NewCredentials
// function.
type Credentials struct {
	params map[string]string
}

// internal function to initialize a Credentials object
func newCredentials() Credentials {
	return Credentials{params: make(map[string]string)}
}

func (c Credentials) papi() (string, bool) {
	val, ok := c.params[credentialsPapiId]
	return val, ok
}

func (c Credentials) sapi() (string, bool) {
	val, ok := c.params[credentialsSapiId]
	return val, ok
}

func (c Credentials) srsa() (string, bool) {
	val, ok := c.params[credentialsSrsaId]
	return val, ok
}

func (c Credentials) host() (string, bool) {
	val, ok := c.params[credentialsHostId]
	return val, ok
}

// viable indicates that the Credentials are not valid but
// will be with only the addition of the host
func (c Credentials) viable() bool {
	if _, ok := c.papi(); ok {
		if _, ok := c.sapi(); ok {
			if _, ok := c.srsa(); ok {
				return true
			}
		}
	}

	return false
}

// valid indicates that all fields of the Credentials are
// present. whether the credentials contain a valid server or
// whether the credentials form a valid set at the server
// is undefined.
func (c Credentials) valid() bool {
	_, ok := c.host()
	return c.viable() && ok
}

// loadCredentials loads all (sets of) Credentials from a file. if
// the file is specified, they are loaded from there. if not, they
// are loaded from the default file.
func loadCredentials(args ...string) (map[string]Credentials, error) {
	var err error
	var path string

	if len(args) > 0 {
		path = args[0]
	} else {
		var u *user.User
		u, _ = user.Current()
		path = filepath.Join(u.HomeDir, ".ubiq", "credentials")
	}

	m := make(map[string]Credentials)

	cfg, err := ini.Load(path)

	if err == nil {
		for _, s := range cfg.Sections() {
			c := newCredentials()

			for _, k := range s.Keys() {
				switch k.Name() {
				case credentialsPapiId:
					fallthrough
				case credentialsSapiId:
					fallthrough
				case credentialsSrsaId:
					fallthrough
				case credentialsHostId:
					c.params[k.Name()] = k.Value()
				}
			}

			// credentials may or may not contain the
			// server/host. they are saved in the map
			// either way
			if c.viable() {
				m[s.Name()] = c
			}
		}
	}

	return m, err
}

// merge populates missing fields in the current credentials
// with those fields from the `other` credentials
func (c *Credentials) merge(other Credentials) {
	if _, ok := c.papi(); !ok {
		c.params[credentialsPapiId] = other.params[credentialsPapiId]
	}
	if _, ok := c.sapi(); !ok {
		c.params[credentialsSapiId] = other.params[credentialsSapiId]
	}
	if _, ok := c.srsa(); !ok {
		c.params[credentialsSrsaId] = other.params[credentialsSrsaId]
	}
	if _, ok := c.host(); !ok {
		c.params[credentialsHostId] = other.params[credentialsHostId]
	}
}

// finalize is called to turn viable credentials into valid
// credentials by adding the host field if necessary. this is
// done by passing the individual fields of the given
// credentials to the set() function.
func (c *Credentials) finalize() error {
	var err error

	err = errors.New("credentials not found")
	if c.viable() {
		err = c.set(
			c.params[credentialsPapiId],
			c.params[credentialsSapiId],
			c.params[credentialsSrsaId],
			c.params[credentialsHostId])
	}

	return err
}

// init encompasses the default behavior of trying to get credentials
// fields from the environment and then supplementing the missing fields
// with those from the default profile in the default file.
func (c *Credentials) init() error {
	if val, ok := os.LookupEnv(credentialsPapiEnvId); ok {
		c.params[credentialsPapiId] = val
	}
	if val, ok := os.LookupEnv(credentialsSapiEnvId); ok {
		c.params[credentialsSapiId] = val
	}
	if val, ok := os.LookupEnv(credentialsSrsaEnvId); ok {
		c.params[credentialsSrsaId] = val
	}
	if val, ok := os.LookupEnv(credentialsHostEnvId); ok {
		c.params[credentialsHostId] = val
	}

	m, _ := loadCredentials()
	c.merge(m[credentialsDefaultProfileId])

	return c.finalize()
}

// load loads the specified profile from the specified file
//
// load takes 0, 1, or 2 arguments. the first argument is the file
// from which to load the credentials. if it is not given or is empty,
// the default file is read. the second argument is the profile. if it
// is not given or is empty, the `default` profile is used if present.
func (c *Credentials) load(args ...string) error {
	var m map[string]Credentials

	if len(args) > 0 && len(args[0]) > 0 {
		m, _ = loadCredentials(args[0])
	} else {
		m, _ = loadCredentials()
	}

	if len(args) > 1 && len(args[1]) > 1 {
		*c = m[args[1]]
	}

	if c, ok := m[credentialsDefaultProfileId]; ok {
		c.merge(c)
	}

	if _, ok := c.host(); !ok {
		val, ok := os.LookupEnv(credentialsHostEnvId)
		if ok {
			c.params[credentialsHostId] = val
		}
	}

	return c.finalize()
}

func (c *Credentials) set(papi, sapi, srsa string, args ...string) error {
	host := credentialsDefaultHost
	if len(args) > 0 && len(args[0]) > 0 {
		host = args[0]
	}

	if !strings.HasPrefix(host, "http://") &&
		!strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}

	c.params[credentialsPapiId] = papi
	c.params[credentialsSapiId] = sapi
	c.params[credentialsSrsaId] = srsa
	c.params[credentialsHostId] = host

	return nil
}

// NewCredentials creats a Credentials object and populates it with the
// caller's credentials according to the number of arguments passed to it.
//
// If 0 arguments are passed to the function, the credentials will be loaded
// from the environmental variables UBIQ_ACCESS_KEY_ID,
// UBIQ_SECRET_SIGNING_KEY, UBIQ_SECRET_CRYPTO_ACCESS_KEY, and UBIQ_SERVER.
// The credentials associated with the "default" profile will be loaded from
// the default credentials file (~/.ubiq/credentials) and used to supplement
// any values missing from the environment.
//
// If 1 or 2 arguments are passed, they are treated as the name of the file
// from which to load credentials and the name of the profile to use,
// respectively. If either argument is empty or missing, the value of the
// parameter as described in the case of 0 arguments will be used.
// Environmental variables are ignored except for UBIQ_SERVER which may still
// override credentials found in the file.
//
// If 3 or 4 arguments are passed, they are treated as the ACCESS_KEY_ID,
// SECRET_SIGNING_KEY, SECRET_CRYPTO_ACCESS_KEY, and SERVER, respectively.
// If SERVER is not specified, it will be assigned the default value. The
// SERVER may specify http:// or https://. If neither is specified, the
// https:// prefix will be added.
func NewCredentials(args ...string) (Credentials, error) {
	var err error

	c := newCredentials()

	switch len(args) {
	case 0:
		err = c.init()
	case 1:
		err = c.load(args[0])
	case 2:
		err = c.load(args[0], args[1])
	case 3:
		err = c.set(args[0], args[1], args[2])
	case 4:
		err = c.set(args[0], args[1], args[2], args[3])
	}

	return c, err
}
