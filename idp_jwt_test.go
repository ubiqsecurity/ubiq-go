package ubiq

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// makeUnsignedTestJwt builds a header.payload.signature string with the given
// payload claims. The signature segment is a placeholder; parseJwt only decodes
// the (unverified) payload.
func makeUnsignedTestJwt(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "none", "typ": "JWT"}
	hj, _ := json.Marshal(header)
	pj, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(hj) + "." +
		base64.RawURLEncoding.EncodeToString(pj) + ".sig"
}

func TestParseJwt(t *testing.T) {
	token := makeUnsignedTestJwt(t, map[string]interface{}{
		"sub":         "abc-123",
		"unique_name": "user@example.com",
		"email":       "user@example.com",
		"exp":         1893456000,
	})

	claims, err := parseJwt(token)
	if err != nil {
		t.Fatalf("parseJwt: %v", err)
	}
	if claims.Sub != "abc-123" {
		t.Errorf("sub = %q, want abc-123", claims.Sub)
	}
	if claims.UniqueName != "user@example.com" {
		t.Errorf("unique_name = %q, want user@example.com", claims.UniqueName)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", claims.Email)
	}
	if claims.Exp != 1893456000 {
		t.Errorf("exp = %d, want 1893456000", claims.Exp)
	}
}

func TestJwtClaimsIdentity(t *testing.T) {
	// claims carrying every relevant field so each case shows the provider
	// picking its specific claim.
	full := jwtIdpClaims{
		Sub:               "00000000-0000-0000-0000-000000000001",
		UniqueName:        "uname@example.com",
		PreferredUsername: "puser@example.com",
		Email:             "email@example.com",
	}

	cases := []struct {
		name     string
		provider string
		claims   jwtIdpClaims
		want     string
	}{
		// Mirrors the backend resolution per provider.
		{name: "self-signed -> email", provider: "selfsigned", claims: full, want: "email@example.com"},
		{name: "ubiq alias -> email", provider: "ubiq", claims: full, want: "email@example.com"},
		{name: "okta -> sub", provider: "okta", claims: full, want: "00000000-0000-0000-0000-000000000001"},
		{name: "okta case-insensitive -> sub", provider: "OKTA", claims: full, want: "00000000-0000-0000-0000-000000000001"},
		{name: "entra -> unique_name", provider: "entra", claims: full, want: "uname@example.com"},
		{
			// preferred_username fallback is deferred until the app-server
			// change merges, so entra without unique_name resolves to empty.
			name:     "entra without unique_name (preferred_username fallback deferred)",
			provider: "entra",
			claims:   jwtIdpClaims{Sub: "guid", PreferredUsername: "puser@example.com"},
			want:     "",
		},
		// Unknown/unset provider mirrors the backend, which has no fallback branch.
		{name: "unknown provider resolves empty", provider: "", claims: full, want: ""},
		{name: "unrecognized provider resolves empty", provider: "auth0", claims: full, want: ""},
		{name: "empty when nothing present", provider: "entra", claims: jwtIdpClaims{}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.claims.identity(tc.provider); got != tc.want {
				t.Errorf("identity(%q) = %q, want %q", tc.provider, got, tc.want)
			}
		})
	}
}

func TestParseJwtInvalid(t *testing.T) {
	if _, err := parseJwt("not-a-jwt"); err == nil {
		t.Error("expected error for token without a payload segment")
	}
	if _, err := parseJwt("aaaa.!!!not-base64!!!.bbbb"); err == nil {
		t.Error("expected error for non-base64 payload")
	}
	if _, err := parseJwt("aaaa." + base64.RawURLEncoding.EncodeToString([]byte("{not json")) + ".bbbb"); err == nil {
		t.Error("expected error for non-JSON payload")
	}
}

func TestIsSelfSignedProvider(t *testing.T) {
	for _, p := range []string{"selfsigned", "Self-Signed", "SELF_SIGNED", "ubiq", " Ubiq "} {
		if !isSelfSignedProvider(p) {
			t.Errorf("isSelfSignedProvider(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"okta", "entra", ""} {
		if isSelfSignedProvider(p) {
			t.Errorf("isSelfSignedProvider(%q) = true, want false", p)
		}
	}
}

func newSelfSignTestCredentials(t *testing.T, key *rsa.PrivateKey, identity string) Credentials {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	keyPem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))

	c := newCredentials()
	config, _ := NewConfiguration("/nonexistent-ubiq-config")
	c.config = &config
	c.config.Idp.Provider = "selfsigned"
	c.config.Idp.SelfSignKey = keyPem
	if identity != "" {
		c.params[credentialsIdpUsernameId] = identity
	}
	return c
}

func TestMakeSelfSignedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := newSelfSignTestCredentials(t, key, "user@example.com")

	token, err := c.makeSelfSignedToken()
	if err != nil {
		t.Fatalf("makeSelfSignedToken: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}

	// The token must carry a valid RS256 signature over header.payload.
	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed[:], sig); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}

	claims, err := parseJwt(token)
	if err != nil {
		t.Fatalf("parseJwt: %v", err)
	}
	if claims.Sub != "user@example.com" {
		t.Errorf("sub = %q, want user@example.com", claims.Sub)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", claims.Email)
	}
	if claims.Exp <= time.Now().Unix() {
		t.Errorf("exp = %d is not in the future", claims.Exp)
	}
}

func TestMakeSelfSignedTokenMissingInputs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Missing identity.
	c := newSelfSignTestCredentials(t, key, "")
	if _, err := c.makeSelfSignedToken(); err == nil {
		t.Error("expected error when identity is missing")
	}

	// Missing self-sign key.
	c = newSelfSignTestCredentials(t, key, "user@example.com")
	c.config.Idp.SelfSignKey = ""
	if _, err := c.makeSelfSignedToken(); err == nil {
		t.Error("expected error when self-sign key is missing")
	}
}

// The JWT object cache refreshes the stored token through a value copy of the
// credentials; the write must be visible to every other copy sharing the
// params map (e.g. the creds held inside cached enc/dec objects).
func TestSetIdpJwtSharedAcrossCopies(t *testing.T) {
	c := newCredentials()
	c.params[credentialsIdpJwtId] = "original"

	copy1 := c
	copy2 := c

	copy1.setIdpJwt("refreshed")

	if val, _ := copy2.idpJwt(); val != "refreshed" {
		t.Errorf("idpJwt via copy = %q, want refreshed", val)
	}
	if val, _ := c.idpJwt(); val != "refreshed" {
		t.Errorf("idpJwt via original = %q, want refreshed", val)
	}
}

// Concurrent readers (request signing, renewal) and writers (token refresh,
// cert renewal storing papi/sapi) on the shared params map must not race.
// Run with -race to make this meaningful.
func TestCredentialsParamsConcurrentAccess(t *testing.T) {
	c := newCredentials()
	c.params[credentialsPapiId] = "papi"
	c.params[credentialsSapiId] = "sapi"

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			c.setIdpJwt("token")
			c.setParam(credentialsPapiId, "papi")
		}
	}()
	for i := 0; i < 1000; i++ {
		c.papi()
		c.sapi()
		c.idpJwt()
	}
	<-done
}
