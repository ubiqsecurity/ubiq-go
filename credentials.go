package ubiq

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-ini/ini"
)

const (
	credentialsPapiId        = "ACCESS_KEY_ID"
	credentialsSapiId        = "SECRET_SIGNING_KEY"
	credentialsSrsaId        = "SECRET_CRYPTO_ACCESS_KEY"
	credentialsHostId        = "SERVER"
	credentialsIdpUsernameId = "IDP_USERNAME"
	credentialsIdpPasswordId = "IDP_PASSWORD"
	credentialsIdpJwtId      = "IDP_JWT"

	credentialsPapiEnvId        = "UBIQ_" + credentialsPapiId
	credentialsSapiEnvId        = "UBIQ_" + credentialsSapiId
	credentialsSrsaEnvId        = "UBIQ_" + credentialsSrsaId
	credentialsHostEnvId        = "UBIQ_" + credentialsHostId
	credentialsIdpUsernameEnvId = "UBIQ_" + credentialsIdpUsernameId
	credentialsIdpPasswordEnvId = "UBIQ_" + credentialsIdpPasswordId
	credentialsIdpJwtEnvId      = "UBIQ_" + credentialsIdpJwtId

	credentialsDefaultProfileId = "default"
	credentialsDefaultHost      = "api.ubiqsecurity.com"
)

// idpAuthMode identifies how a Credentials object authenticates against
// the Ubiq platform when IDP integration is in use.
type idpAuthMode int

const (
	idpModeNone idpAuthMode = iota
	// idpModeUser authenticates against an external IDP (okta/entra) with
	// an IDP username and password via the OAuth password grant.
	idpModeUser
	// idpModeJwt uses a caller-supplied, pre-issued JWT access token.
	idpModeJwt
	// idpModeSelfSigned signs a short-lived token locally for a given
	// identity (self-managed IDP, no external IDP involved).
	idpModeSelfSigned
)

// isSelfSignedProvider reports whether the configured IDP provider denotes
// the self-managed (self-signed) flow.
func isSelfSignedProvider(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "selfsigned", "self-signed", "self_signed", "ubiq":
		return true
	}
	return false
}

// Credentials holds the caller's credentials which are used
// to authenticate the caller to the Ubiq platform. Credentials
// must always be created/initialized via the NewCredentials
// function.
type Credentials struct {
	params map[string]string
	// paramsMu guards params. The map is shared by every value copy of a
	// Credentials object (and so by the enc/dec objects built from it), and
	// is written after construction by IDP cert renewal and the JWT object
	// cache's token refresh.
	paramsMu *sync.RWMutex
	// idpRenewMu serializes IDP cert renewal so concurrent operations on a
	// shared enc/dec object cannot renew twice or read the cert fields
	// mid-write. It is separate from paramsMu because renewal itself writes
	// params through setParam.
	idpRenewMu *sync.Mutex

	config *Configuration
	cache  cache

	idpMode                idpAuthMode
	idpCsr                 string
	idpBase64Cert          string
	idpCertExpires         time.Time
	idpEncryptedPrivateKey string
	initialized            bool
}

// internal function to initialize a Credentials object
func newCredentials() Credentials {
	return Credentials{
		params:      make(map[string]string),
		paramsMu:    new(sync.RWMutex),
		idpRenewMu:  new(sync.Mutex),
		initialized: false,
	}
}

// getParam and setParam synchronize access to the shared params map. The
// mutex may be nil for credentials built outside newCredentials (e.g. zero
// values during loading); those are not shared across goroutines yet.
func (c Credentials) getParam(key string) (string, bool) {
	if c.paramsMu != nil {
		c.paramsMu.RLock()
		defer c.paramsMu.RUnlock()
	}
	val, ok := c.params[key]
	return val, ok
}

func (c Credentials) setParam(key, val string) {
	if c.paramsMu != nil {
		c.paramsMu.Lock()
		defer c.paramsMu.Unlock()
	}
	c.params[key] = val
}

func (c Credentials) papi() (string, bool) {
	return c.getParam(credentialsPapiId)
}

func (c Credentials) sapi() (string, bool) {
	return c.getParam(credentialsSapiId)
}

func (c Credentials) srsa() (string, bool) {
	return c.getParam(credentialsSrsaId)
}

func (c Credentials) host() (string, bool) {
	return c.getParam(credentialsHostId)
}

func (c Credentials) idpUsername() (string, bool) {
	return c.getParam(credentialsIdpUsernameId)
}

func (c Credentials) idpPassword() (string, bool) {
	return c.getParam(credentialsIdpPasswordId)
}

func (c Credentials) idpJwt() (string, bool) {
	return c.getParam(credentialsIdpJwtId)
}

// setIdpJwt replaces the stored IDP JWT. The JWT object cache uses it to keep
// the freshest presented token available for the next cert renewal.
func (c Credentials) setIdpJwt(jwt string) {
	c.setParam(credentialsIdpJwtId, jwt)
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
	} else if val, ok := c.idpJwt(); ok && len(val) > 0 {
		return true
	} else if _, ok := c.idpUsername(); ok {
		if _, ok := c.idpPassword(); ok {
			return true
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
					fallthrough
				case credentialsIdpUsernameId:
					fallthrough
				case credentialsIdpPasswordId:
					fallthrough
				case credentialsIdpJwtId:
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
		c.params[credentialsPapiId] =
			other.params[credentialsPapiId]
	}
	if _, ok := c.sapi(); !ok {
		c.params[credentialsSapiId] =
			other.params[credentialsSapiId]
	}
	if _, ok := c.srsa(); !ok {
		c.params[credentialsSrsaId] =
			other.params[credentialsSrsaId]
	}
	if _, ok := c.host(); !ok {
		c.params[credentialsHostId] =
			other.params[credentialsHostId]
	}
	if _, ok := c.idpUsername(); !ok {
		c.params[credentialsIdpUsernameId] =
			other.params[credentialsIdpUsernameId]
	}
	if _, ok := c.idpPassword(); !ok {
		c.params[credentialsIdpPasswordId] =
			other.params[credentialsIdpPasswordId]
	}
	if _, ok := c.idpJwt(); !ok {
		c.params[credentialsIdpJwtId] =
			other.params[credentialsIdpJwtId]
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
	if val, ok := os.LookupEnv(credentialsIdpUsernameEnvId); ok {
		c.params[credentialsIdpUsernameId] = val
	}
	if val, ok := os.LookupEnv(credentialsIdpPasswordEnvId); ok {
		c.params[credentialsIdpPasswordId] = val
	}
	if val, ok := os.LookupEnv(credentialsIdpJwtEnvId); ok {
		c.params[credentialsIdpJwtId] = val
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

func (c *Credentials) Close() {
	c.cache.cache.Close()
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
		// file
		err = c.load(args[0])
	case 2:
		// file, profile
		err = c.load(args[0], args[1])
	case 3:
		// papi, sapi, srsa
		err = c.set(args[0], args[1], args[2])
	case 4:
		// papi, sapi, srsa, host
		err = c.set(args[0], args[1], args[2], args[3])
	}

	if err != nil {
		return c, err
	}

	// Intialize default configuration
	config, err := NewConfiguration()
	if err != nil {
		return c, err
	}
	c.config = &config

	// Initialize cache
	c.cache, err = initializeCache(c.config)

	return c, err
}

type CredentialsParams struct {
	AccessKeyId           string
	SecretSigningKey      string
	SecretCryptoAccessKey string

	IdpUsername string
	IdpPassword string
	IdpJwt      string

	Host string

	CredentialsFile string
	Profile         string

	Config *Configuration
}

type CredentialBuilder interface {
	Build()
}

func (params *CredentialsParams) Build() (Credentials, error) {
	var err error
	c := newCredentials()

	if params.AccessKeyId != "" && params.CredentialsFile != "" {
		return c, fmt.Errorf("only one, credentials values or credentials file, should be set")
	}

	// Load base credentials. For IDP flows there may be no static
	// (papi/sapi/srsa) credentials present, so any error here is deferred
	// and only returned if the credentials turn out to be non-IDP.
	var loadErr error
	if params.AccessKeyId != "" && params.SecretSigningKey != "" && params.SecretCryptoAccessKey != "" {
		// Load from individual values
		loadErr = c.set(params.AccessKeyId, params.SecretSigningKey, params.SecretCryptoAccessKey, params.Host)
	} else if params.CredentialsFile != "" {
		// Load from file/profile
		loadErr = c.load(params.CredentialsFile, params.Profile)
	} else {
		// Load from ENV variables
		loadErr = c.init()
	}

	// load() may replace the receiver with a zero value when the profile is
	// absent; make sure the params map remains usable.
	if c.params == nil {
		c.params = make(map[string]string)
	}
	if c.paramsMu == nil {
		c.paramsMu = new(sync.RWMutex)
	}
	if c.idpRenewMu == nil {
		c.idpRenewMu = new(sync.Mutex)
	}

	// Resolve configuration first; it is needed to detect the self-signed
	// (self-managed) IDP provider.
	if params.Config == nil {
		config, cerr := NewConfiguration()
		if cerr != nil {
			return c, cerr
		}
		c.config = &config
	} else {
		c.config = params.Config
	}

	// Explicit IDP parameters take precedence over file/env values.
	if params.IdpUsername != "" {
		c.params[credentialsIdpUsernameId] = params.IdpUsername
	}
	if params.IdpPassword != "" {
		c.params[credentialsIdpPasswordId] = params.IdpPassword
	}
	if params.IdpJwt != "" {
		c.params[credentialsIdpJwtId] = params.IdpJwt
	}

	// For the self-managed provider the identity may be supplied via
	// configuration when it is not provided as an IDP username.
	if isSelfSignedProvider(c.config.Idp.Provider) {
		if _, ok := c.idpUsername(); !ok && c.config.Idp.SelfSignIdentity != "" {
			c.params[credentialsIdpUsernameId] = c.config.Idp.SelfSignIdentity
		}
	}

	jwt, hasJwt := c.idpJwt()
	username, hasUser := c.idpUsername()
	switch {
	case hasJwt && len(jwt) > 0:
		c.idpMode = idpModeJwt
	case isSelfSignedProvider(c.config.Idp.Provider) && hasUser && len(username) > 0:
		c.idpMode = idpModeSelfSigned
	case hasUser && len(username) > 0:
		c.idpMode = idpModeUser
	}

	// Non-IDP credentials must have loaded cleanly.
	if c.idpMode == idpModeNone && loadErr != nil {
		return c, loadErr
	}

	// Ensure a host is set for IDP flows that bypassed finalize().
	if c.idpMode != idpModeNone {
		host := params.Host
		if host == "" {
			if val, ok := c.host(); ok {
				host = val
			}
		}
		if host == "" {
			if val, ok := os.LookupEnv(credentialsHostEnvId); ok {
				host = val
			}
		}
		if host == "" {
			host = credentialsDefaultHost
		}
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			host = "https://" + host
		}
		c.params[credentialsHostId] = host
	}

	// Create cache for storing data
	c.cache, err = initializeCache(c.config)
	if err != nil {
		return c, err
	}

	if c.idpMode != idpModeNone {
		err = c.initIdp()
	}

	return c, err
}
