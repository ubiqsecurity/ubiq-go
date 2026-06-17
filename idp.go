package ubiq

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/youmark/pkcs8"
)

type OauthResponse struct {
	AccessToken string `json:"access_token"`
}

type SsoResponse struct {
	ApiCert      string `json:"api_cert"`
	PublicValue  string `json:"public_value"`
	SigningValue string `json:"signing_value"`
}

// jwtIdpClaims holds the subset of JWT payload claims the library uses to
// identify the user behind a token.
type jwtIdpClaims struct {
	Sub               string `json:"sub"`
	UniqueName        string `json:"unique_name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Exp               int64  `json:"exp"`
}

// identity returns the local identifier for the token, mirroring exactly how the
// backend resolves the user from the configured IDP provider:
//
//	self-signed -> email
//	okta        -> sub
//	entra       -> unique_name (||preferred_username deferred, see below)
//
// For OIDC id tokens sub is a globally unique opaque identifier rather than the
// user's name, which is why entra uses the username claim. The authoritative
// user match always happens server-side from the token itself; this value is
// only used locally for caching and identity keying. An unrecognized provider
// returns "" to mirror the backend, which has no fallback branch.
func (c jwtIdpClaims) identity(provider string) string {
	switch {
	case isSelfSignedProvider(provider):
		return c.Email
	case strings.EqualFold(provider, "okta"):
		return c.Sub
	case strings.EqualFold(provider, "entra"):
		// TODO(next release): fall back to preferred_username when unique_name
		// is absent (OIDC id tokens), once the matching app-server change that
		// resolves preferred_username is merged. Until then entra stays in
		// lockstep with the live backend, which uses unique_name only.
		//   if c.UniqueName != "" {
		//       return c.UniqueName
		//   }
		//   return c.PreferredUsername
		return c.UniqueName
	}
	return ""
}

// parseJwt decodes the (unverified) payload of a JWT and returns the claims
// the library cares about. The token is only decoded locally; it is validated
// server-side when presented to the SSO endpoint.
func parseJwt(token string) (jwtIdpClaims, error) {
	var claims jwtIdpClaims

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return claims, fmt.Errorf("invalid JWT token format")
	}

	// JWTs use base64url without padding; tolerate tokens that include it.
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return claims, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("invalid JWT payload: %w", err)
	}

	return claims, nil
}

// makeSelfSignedToken mints a short-lived RS256 JWT for the configured
// self-managed identity, signed with the configured self-sign key. The token
// is then presented to the SSO endpoint exactly like an external IDP token.
func (c Credentials) makeSelfSignedToken() (string, error) {
	identity, _ := c.idpUsername()
	if identity == "" {
		return "", fmt.Errorf("self-signed IDP requires an identity (IDP_USERNAME or self_sign_identity)")
	}
	if c.config.Idp.SelfSignKey == "" {
		return "", fmt.Errorf("self-signed IDP requires self_sign_key in the configuration")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(c.config.Idp.SelfSignKey))
	if err != nil {
		return "", fmt.Errorf("invalid self-sign key: %w", err)
	}

	now := time.Now()
	notBefore := now.Add(-30 * time.Millisecond).Unix()
	claims := jwt.MapClaims{
		"iss":   "Ubiq",
		"aud":   "",
		"sub":   identity,
		"email": identity,
		"jti":   generateRandomB64Str(16),
		"iat":   notBefore,
		"nbf":   notBefore,
		"exp":   now.Add(10 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// IdpLoginJwt performs an OAuth password-grant login against the external IDP
// described by cfg and returns the resulting JWT access token, suitable for
// the JWT-based structured API (StructuredEncryptJwt / StructuredDecryptJwt).
// cfg must carry the IDP provider settings (provider, tenant id, client
// secret, token endpoint url); if cfg is nil the default configuration is
// loaded.
func IdpLoginJwt(idpUsername, idpPassword string, cfg *Configuration) (string, error) {
	if cfg == nil {
		config, err := NewConfiguration()
		if err != nil {
			return "", err
		}
		cfg = &config
	}

	c := newCredentials()
	c.config = cfg
	c.params[credentialsIdpUsernameId] = idpUsername
	c.params[credentialsIdpPasswordId] = idpPassword

	return c.getOauthToken()
}

func (c Credentials) getOauthToken() (string, error) {
	client := &http.Client{}

	data := url.Values{}
	idpUser, _ := c.idpUsername()
	idpPass, _ := c.idpPassword()
	data.Set("client_id", c.config.Idp.TenantId)
	data.Set("client_secret", c.config.Idp.ClientSecret)
	data.Set("username", idpUser)
	data.Set("password", idpPass)
	data.Set("grant_type", "password")

	if c.config.Idp.Provider == "okta" {
		data.Set("scope", "openid offline_access okta.users.read okta.groups.read")
	} else if c.config.Idp.Provider == "entra" {
		data.Set("scope", fmt.Sprintf("api://%s/.default", c.config.Idp.TenantId))
	} else {
		return "", fmt.Errorf("unknown or no IDP provier specified: %s Check your configuration and try again", c.config.Idp.Provider)
	}

	resp, err := client.PostForm(
		c.config.Idp.TokenEndpointUrl,
		data,
	)

	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status (%v) Unable to fetch token from %s", resp.StatusCode, c.config.Idp.TokenEndpointUrl)
	}
	oauthResp := new(OauthResponse)
	err = json.NewDecoder(resp.Body).Decode(oauthResp)
	if err != nil {
		return "", err
	}

	return oauthResp.AccessToken, nil
}

func (c *Credentials) initIdp() error {
	// generate srsa
	srsa := generateRandomB64Str(33)

	c.params[credentialsSrsaId] = srsa

	// generate keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	// PEM format Private Key
	// privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

	// Encrypt and Save PK
	encryptedPrivateKeyBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(privateKey, []byte(srsa))
	encryptedPrivateKey := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedPrivateKeyBytes})
	if err != nil {
		return err
	}
	c.idpEncryptedPrivateKey = string(encryptedPrivateKey)

	// make csr
	subj := pkix.Name{
		CommonName:         generateRandomB64Str(18),
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Diego"},
		Organization:       []string{"Ubiq Security, Inc."},
		OrganizationalUnit: []string{"Ubiq Platform"},
	}
	csrTemplate := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return err
	}
	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	c.idpCsr = string(csrPem)
	// get idp token and cert
	err = c.getIdpTokenAndCert()
	if err != nil {
		return err
	}

	// initialized
	c.initialized = true

	return nil
}

func generateRandomB64Str(length int) string {
	randByteArr := make([]byte, length)
	rand.Read(randByteArr)
	generatedB64Str := base64.StdEncoding.EncodeToString(randByteArr)
	return generatedB64Str
}

func (c *Credentials) getIdpTokenAndCert() error {
	var token string
	var err error

	switch c.idpMode {
	case idpModeJwt:
		token, _ = c.idpJwt()
		claims, perr := parseJwt(token)
		if perr != nil {
			return perr
		}
		// Identify the user locally (used for caching/identity). The
		// authoritative match happens server-side from the token itself.
		c.setParam(credentialsIdpUsernameId, claims.identity(c.config.Idp.Provider))
	case idpModeSelfSigned:
		token, err = c.makeSelfSignedToken()
		if err != nil {
			return err
		}
	default:
		token, err = c.getOauthToken()
		if err != nil {
			return err
		}
	}

	sso, err := c.getSso(token, c.idpCsr)
	if err != nil {
		return err
	}

	// Save Access Key
	c.setParam(credentialsPapiId, sso.PublicValue)
	// Save Secret Singing Value
	c.setParam(credentialsSapiId, sso.SigningValue)

	c.idpBase64Cert = base64.StdEncoding.EncodeToString([]byte(sso.ApiCert))
	certBlock, _ := pem.Decode([]byte(sso.ApiCert))
	if certBlock == nil {
		return fmt.Errorf("invalid SSO certificate: not PEM encoded")
	}
	idpCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	c.idpCertExpires = idpCert.NotAfter.Add(-1 * time.Minute)
	return nil
}

// renewIdpCert refreshes the server-issued API cert when it has expired and
// returns the current base64 cert. The renewal check and the cert read happen
// under a lock so concurrent operations on a shared object cannot renew twice
// or see a half-written cert. For idpModeJwt the exchange presents the most
// recently stored JWT, so a failure here usually means the stored token has
// itself expired.
func (c *Credentials) renewIdpCert() (string, error) {
	isIdp, err := c.isIdp()
	if err != nil {
		return "", err
	}
	if !isIdp {
		return "", nil
	}

	if c.idpRenewMu != nil {
		c.idpRenewMu.Lock()
		defer c.idpRenewMu.Unlock()
	}
	if c.idpCertExpires.Before(time.Now()) {
		if err := c.getIdpTokenAndCert(); err != nil {
			return "", fmt.Errorf("unable to renew IDP certificate: %w", err)
		}
	}
	return c.idpBase64Cert, nil
}

// validateIdpToken forces an SSO exchange using the currently stored IDP token,
// regardless of whether the existing cert is still valid. The exchange is the
// validation: the server rejects (401) a token that is invalid or expired, so a
// nil return means the stored token was accepted. Used by the JWT object cache
// to validate a freshly presented token instead of trusting it until the cert
// happens to expire.
func (c *Credentials) validateIdpToken() error {
	if c.idpRenewMu != nil {
		c.idpRenewMu.Lock()
		defer c.idpRenewMu.Unlock()
	}
	if err := c.getIdpTokenAndCert(); err != nil {
		return fmt.Errorf("unable to validate IDP token: %w", err)
	}
	return nil
}

func (c Credentials) getSso(accessToken, csr string) (SsoResponse, error) {
	client := &http.Client{}
	host, _ := c.host()
	url := fmt.Sprintf("%s/%s/api/v3/scim/sso", host, c.config.Idp.CustomerId)
	bodyMap := map[string]string{
		"csr": csr,
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return SsoResponse{}, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return SsoResponse{}, err
	}
	req.Header = map[string][]string{
		"Authorization": {fmt.Sprintf("Bearer %s", accessToken)},
		"Accept":        {"application/json"},
		"Cache-control": {"no-cache"},
		"content-type":  {"application/json"},
	}
	resp, err := client.Do(req)
	if err != nil {
		return SsoResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SsoResponse{}, fmt.Errorf("status (%v) unable to fetch SSO certificate from %s", resp.StatusCode, url)
	}
	ssoResponse := new(SsoResponse)
	err = json.NewDecoder(resp.Body).Decode(ssoResponse)
	if err != nil {
		return SsoResponse{}, err
	}

	return *ssoResponse, nil
}

func (c Credentials) isIdp() (bool, error) {
	if c.idpMode == idpModeNone {
		return false, nil
	}

	if !c.initialized {
		return false, fmt.Errorf("credentials have not been initialized, but IDP authentication has been requested")
	}

	return true, nil
}
