package ubiq

// Integration tests for IDP / JWT based structured encryption. These mirror the
// Java SDK's UbiqIdpTest and exercise the live Ubiq platform, so they are gated
// on the UBIQ_UNITTEST_IDP_* environment variables and skip when those are not
// present.
//
// Required env vars (describe the IDP configuration and a read/write user):
//
//	UBIQ_UNITTEST_IDP_TYPE                (provider: okta | entra)
//	UBIQ_UNITTEST_IDP_CUSTOMER_ID
//	UBIQ_UNITTEST_IDP_TOKEN_ENDPOINT_URL
//	UBIQ_UNITTEST_IDP_TENANT_ID
//	UBIQ_UNITTEST_IDP_CLIENT_SECRET
//	UBIQ_UNITTEST_IDP_SERVER
//	UBIQ_UNITTEST_IDP_USERNAME
//	UBIQ_UNITTEST_IDP_PASSWORD
//
// Optional (enable the multi-user permission tests):
//
//	UBIQ_UNITTEST_IDP_RO_USERNAME / UBIQ_UNITTEST_IDP_RO_PASSWORD   (read only)
//	UBIQ_UNITTEST_IDP_WO_USERNAME / UBIQ_UNITTEST_IDP_WO_PASSWORD   (write only)

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	envIdpType             = "UBIQ_UNITTEST_IDP_TYPE"
	envIdpCustomerId       = "UBIQ_UNITTEST_IDP_CUSTOMER_ID"
	envIdpTokenEndpointUrl = "UBIQ_UNITTEST_IDP_TOKEN_ENDPOINT_URL"
	envIdpTenantId         = "UBIQ_UNITTEST_IDP_TENANT_ID"
	envIdpClientSecret     = "UBIQ_UNITTEST_IDP_CLIENT_SECRET"
	envIdpServer           = "UBIQ_UNITTEST_IDP_SERVER"
	envIdpUsername         = "UBIQ_UNITTEST_IDP_USERNAME"
	envIdpPassword         = "UBIQ_UNITTEST_IDP_PASSWORD"
	envIdpRoUsername       = "UBIQ_UNITTEST_IDP_RO_USERNAME"
	envIdpRoPassword       = "UBIQ_UNITTEST_IDP_RO_PASSWORD"
	envIdpWoUsername       = "UBIQ_UNITTEST_IDP_WO_USERNAME"
	envIdpWoPassword       = "UBIQ_UNITTEST_IDP_WO_PASSWORD"

	// envIdpPermissions opts in to the permission-enforcement tests
	// (TestIdpWriteOnly / TestIdpReadOnly). These assert that a restricted
	// user is denied an operation, which only holds when the RO/WO users are
	// configured with restricted dataset permissions server-side. They mirror
	// the @Ignore'd jwtWriteOnlyIdp / jwtReadOnlyIdp tests in the Java SDK and
	// are off by default so a permissive dev account does not fail the suite.
	envIdpPermissions = "UBIQ_UNITTEST_IDP_PERMISSIONS"

	// envIdpSelfSignKeyFile points at a PEM RSA private key and enables
	// TestIdpSelfSigned (with UBIQ_UNITTEST_IDP_TYPE set to the self-signed
	// provider). The server-side directory must hold the matching public key.
	envIdpSelfSignKeyFile = "UBIQ_UNITTEST_IDP_SELF_SIGN_KEY_FILE"
)

const (
	idpDatasetSSN      = "SSN"
	idpDatasetInt32    = "integer32"
	idpDatasetInt64    = "integer64"
	idpDatasetDate     = "date"
	idpDatasetDateTime = "datetime"
)

// idpTestConfig builds a Configuration from the UBIQ_UNITTEST_IDP_* env vars,
// skipping the test when the IDP provider is not configured. It also exports
// UBIQ_SERVER so the JWT static API (which has no host parameter) targets the
// same server, matching the Java test workflow.
func idpTestConfig(t *testing.T) *Configuration {
	t.Helper()

	provider := os.Getenv(envIdpType)
	if provider != "okta" && provider != "entra" {
		// The OAuth password-grant tests only apply to external IDPs; the
		// self-signed provider is covered by TestIdpSelfSigned.
		t.Skipf("IDP integration test skipped: %s is not okta or entra", envIdpType)
	}

	cfgJson := fmt.Sprintf(`{
		"idp": {
			"provider": %q,
			"ubiq_customer_id": %q,
			"idp_token_endpoint_url": %q,
			"idp_tenant_id": %q,
			"idp_client_secret": %q
		}
	}`,
		provider,
		os.Getenv(envIdpCustomerId),
		os.Getenv(envIdpTokenEndpointUrl),
		os.Getenv(envIdpTenantId),
		os.Getenv(envIdpClientSecret),
	)

	cfg, err := NewConfigurationFromJson(cfgJson)
	if err != nil {
		t.Fatalf("building IDP configuration: %v", err)
	}

	if server := os.Getenv(envIdpServer); server != "" {
		os.Setenv(credentialsHostEnvId, server)
	}

	return &cfg
}

// idpUserPass returns the username/password for a user role, skipping the test
// when the credentials are not configured.
func idpUserPass(t *testing.T, userEnv, passEnv string) (string, string) {
	t.Helper()
	user := os.Getenv(userEnv)
	pass := os.Getenv(passEnv)
	if user == "" || pass == "" {
		t.Skipf("IDP integration test skipped: %s / %s not set", userEnv, passEnv)
	}
	return user, pass
}

// idpJwt mints a JWT for the given user via the OAuth password grant.
func idpJwt(t *testing.T, cfg *Configuration, userEnv, passEnv string) string {
	t.Helper()
	user, pass := idpUserPass(t, userEnv, passEnv)
	jwt, err := IdpLoginJwt(user, pass, cfg)
	if err != nil {
		t.Fatalf("IdpLoginJwt(%s): %v", userEnv, err)
	}
	if jwt == "" {
		t.Fatalf("IdpLoginJwt(%s) returned an empty token", userEnv)
	}
	return jwt
}

// idpCredentials builds IDP credentials for the given user via the password
// grant (the direct, non-JWT path).
func idpCredentials(t *testing.T, cfg *Configuration, userEnv, passEnv string) Credentials {
	t.Helper()
	user, pass := idpUserPass(t, userEnv, passEnv)
	creds, err := (&CredentialsParams{
		IdpUsername: user,
		IdpPassword: pass,
		Host:        os.Getenv(envIdpServer),
		Config:      cfg,
	}).Build()
	if err != nil {
		t.Fatalf("building IDP credentials for %s: %v", userEnv, err)
	}
	return creds
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// TestIdpEncryptSSN exercises the direct IDP-credential path: structured
// encrypt/decrypt + encrypt-for-search, plus an unstructured round trip.
func TestIdpEncryptSSN(t *testing.T) {
	cfg := idpTestConfig(t)
	creds := idpCredentials(t, cfg, envIdpUsername, envIdpPassword)

	plainText := "123-45-6789"

	enc, err := NewStructuredEncryption(creds)
	if err != nil {
		t.Fatalf("NewStructuredEncryption: %v", err)
	}
	defer enc.Close()

	ct, err := enc.Cipher(idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("Cipher: %v", err)
	}

	cts, err := enc.CipherForSearch(idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("CipherForSearch: %v", err)
	}
	if !contains(cts, ct) {
		t.Errorf("CipherForSearch result %v does not contain %q", cts, ct)
	}

	dec, err := NewStructuredDecryption(creds)
	if err != nil {
		t.Fatalf("NewStructuredDecryption: %v", err)
	}
	defer dec.Close()

	pt, err := dec.Cipher(idpDatasetSSN, ct, nil)
	if err != nil {
		t.Fatalf("decrypt Cipher: %v", err)
	}
	if pt != plainText {
		t.Errorf("decrypted %q, want %q", pt, plainText)
	}

	// Unstructured round trip with the same IDP credentials.
	unstructured := []byte("this is a test")
	uct, err := Encrypt(creds, unstructured)
	if err != nil {
		t.Fatalf("unstructured Encrypt: %v", err)
	}
	upt, err := Decrypt(creds, uct)
	if err != nil {
		t.Fatalf("unstructured Decrypt: %v", err)
	}
	if !bytes.Equal(unstructured, upt) {
		t.Errorf("unstructured round trip mismatch: got %q", upt)
	}
}

// TestIdpJwt exercises the JWT static API: encrypt, decrypt and for-search.
func TestIdpJwt(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	plainText := "123-45-6789"

	ct, err := StructuredEncryptJwt(jwt, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("StructuredEncryptJwt: %v", err)
	}
	pt, err := StructuredDecryptJwt(jwt, cfg, idpDatasetSSN, ct, nil)
	if err != nil {
		t.Fatalf("StructuredDecryptJwt: %v", err)
	}
	if pt != plainText {
		t.Errorf("decrypted %q, want %q", pt, plainText)
	}

	cts, err := StructuredEncryptForSearchJwt(jwt, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("StructuredEncryptForSearchJwt: %v", err)
	}
	if !contains(cts, ct) {
		t.Errorf("for-search result %v does not contain %q", cts, ct)
	}
}

// TestIdpJwtRepeated confirms repeated encrypt/decrypt cycles reuse the cached
// objects and stay consistent.
func TestIdpJwtRepeated(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	plainText := "123-45-6789"
	for i := 0; i < 3; i++ {
		ct, err := StructuredEncryptJwt(jwt, cfg, idpDatasetSSN, plainText, nil)
		if err != nil {
			t.Fatalf("encrypt cycle %d: %v", i, err)
		}
		pt, err := StructuredDecryptJwt(jwt, cfg, idpDatasetSSN, ct, nil)
		if err != nil {
			t.Fatalf("decrypt cycle %d: %v", i, err)
		}
		if pt != plainText {
			t.Errorf("cycle %d decrypted %q, want %q", i, pt, plainText)
		}
	}
}

// TestIdpJwtLoadCache pre-loads a dataset and then encrypts for search.
func TestIdpJwtLoadCache(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	if err := StructuredLoadCacheJwt(jwt, cfg, []string{idpDatasetSSN}); err != nil {
		t.Fatalf("StructuredLoadCacheJwt: %v", err)
	}
	if _, err := StructuredEncryptForSearchJwt(jwt, cfg, idpDatasetSSN, "123-45-6789", nil); err != nil {
		t.Fatalf("StructuredEncryptForSearchJwt after LoadCache: %v", err)
	}
}

func TestIdpJwtInt32(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	if err := StructuredLoadCacheJwt(jwt, cfg, []string{idpDatasetInt32}); err != nil {
		t.Fatalf("StructuredLoadCacheJwt: %v", err)
	}

	for _, v := range []int32{-99999999, -1, 0, 1, 99999999} {
		ct, err := StructuredEncryptInt32Jwt(jwt, cfg, idpDatasetInt32, v, nil)
		if err != nil {
			t.Fatalf("encrypt %d: %v", v, err)
		}
		pt, err := StructuredDecryptInt32Jwt(jwt, cfg, idpDatasetInt32, ct, nil)
		if err != nil {
			t.Fatalf("decrypt %d: %v", v, err)
		}
		if pt != v {
			t.Errorf("decrypted %d, want %d", pt, v)
		}

		cts, err := StructuredEncryptInt32ForSearchJwt(jwt, cfg, idpDatasetInt32, v, nil)
		if err != nil {
			t.Fatalf("for-search %d: %v", v, err)
		}
		found := false
		for _, c := range cts {
			if c == ct {
				found = true
			}
		}
		if !found {
			t.Errorf("for-search %d did not contain %d", v, ct)
		}
	}
}

func TestIdpJwtInt64(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	if err := StructuredLoadCacheJwt(jwt, cfg, []string{idpDatasetInt64}); err != nil {
		t.Fatalf("StructuredLoadCacheJwt: %v", err)
	}

	for _, v := range []int64{-9999999999999999, -1, 0, 1, 9999999999999999} {
		ct, err := StructuredEncryptInt64Jwt(jwt, cfg, idpDatasetInt64, v, nil)
		if err != nil {
			t.Fatalf("encrypt %d: %v", v, err)
		}
		pt, err := StructuredDecryptInt64Jwt(jwt, cfg, idpDatasetInt64, ct, nil)
		if err != nil {
			t.Fatalf("decrypt %d: %v", v, err)
		}
		if pt != v {
			t.Errorf("decrypted %d, want %d", pt, v)
		}

		cts, err := StructuredEncryptInt64ForSearchJwt(jwt, cfg, idpDatasetInt64, v, nil)
		if err != nil {
			t.Fatalf("for-search %d: %v", v, err)
		}
		found := false
		for _, c := range cts {
			if c == ct {
				found = true
			}
		}
		if !found {
			t.Errorf("for-search %d did not contain %d", v, ct)
		}
	}
}

func TestIdpJwtDate(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	if err := StructuredLoadCacheJwt(jwt, cfg, []string{idpDatasetDate}); err != nil {
		t.Fatalf("StructuredLoadCacheJwt: %v", err)
	}

	dates := []time.Time{
		time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Now().UTC().Truncate(24 * time.Hour),
		time.Date(2738, 11, 28, 0, 0, 0, 0, time.UTC),
	}
	for _, d := range dates {
		ct, err := StructuredEncryptDateJwt(jwt, cfg, idpDatasetDate, d, nil)
		if err != nil {
			t.Fatalf("encrypt %s: %v", d, err)
		}
		pt, err := StructuredDecryptDateJwt(jwt, cfg, idpDatasetDate, ct, nil)
		if err != nil {
			t.Fatalf("decrypt %s: %v", d, err)
		}
		if !pt.Equal(d) {
			t.Errorf("decrypted %s, want %s", pt, d)
		}

		cts, err := StructuredEncryptDateForSearchJwt(jwt, cfg, idpDatasetDate, d, nil)
		if err != nil {
			t.Fatalf("for-search %s: %v", d, err)
		}
		found := false
		for _, c := range cts {
			if c.Equal(ct) {
				found = true
			}
		}
		if !found {
			t.Errorf("for-search %s did not contain %s", d, ct)
		}
	}
}

func TestIdpJwtDateTime(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	if err := StructuredLoadCacheJwt(jwt, cfg, []string{idpDatasetDateTime}); err != nil {
		t.Fatalf("StructuredLoadCacheJwt: %v", err)
	}

	times := []time.Time{
		time.Date(1653, 2, 10, 6, 13, 21, 0, time.UTC),
		time.Now().UTC().Truncate(time.Second),
		time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2286, 11, 20, 17, 46, 39, 0, time.UTC),
	}
	for _, d := range times {
		ct, err := StructuredEncryptDateTimeJwt(jwt, cfg, idpDatasetDateTime, d, nil)
		if err != nil {
			t.Fatalf("encrypt %s: %v", d, err)
		}
		pt, err := StructuredDecryptDateTimeJwt(jwt, cfg, idpDatasetDateTime, ct, nil)
		if err != nil {
			t.Fatalf("decrypt %s: %v", d, err)
		}
		if !pt.Equal(d) {
			t.Errorf("decrypted %s, want %s", pt, d)
		}

		cts, err := StructuredEncryptDateTimeForSearchJwt(jwt, cfg, idpDatasetDateTime, d, nil)
		if err != nil {
			t.Fatalf("for-search %s: %v", d, err)
		}
		found := false
		for _, c := range cts {
			if c.Equal(ct) {
				found = true
			}
		}
		if !found {
			t.Errorf("for-search %s did not contain %s", d, ct)
		}
	}
}

// TestIdpJwtCredentials builds Credentials from a JWT (CredentialsParams.IdpJwt)
// and uses them directly with a StructuredEncryption object.
func TestIdpJwtCredentials(t *testing.T) {
	cfg := idpTestConfig(t)
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	creds, err := (&CredentialsParams{
		IdpJwt: jwt,
		Host:   os.Getenv(envIdpServer),
		Config: cfg,
	}).Build()
	if err != nil {
		t.Fatalf("building JWT credentials: %v", err)
	}

	enc, err := NewStructuredEncryption(creds)
	if err != nil {
		t.Fatalf("NewStructuredEncryption: %v", err)
	}
	defer enc.Close()
	dec, err := NewStructuredDecryption(creds)
	if err != nil {
		t.Fatalf("NewStructuredDecryption: %v", err)
	}
	defer dec.Close()

	plainText := "123-45-6789"
	for i := 0; i < 10; i++ {
		ct, err := enc.Cipher(idpDatasetSSN, plainText, nil)
		if err != nil {
			t.Fatalf("encrypt cycle %d: %v", i, err)
		}
		pt, err := dec.Cipher(idpDatasetSSN, ct, nil)
		if err != nil {
			t.Fatalf("decrypt cycle %d: %v", i, err)
		}
		if pt != plainText {
			t.Errorf("cycle %d decrypted %q, want %q", i, pt, plainText)
		}
	}
}

// TestIdpJwtReset confirms CloseJwt clears cached state and that the JWT API
// keeps working afterwards.
func TestIdpJwtReset(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpUsername, envIdpPassword)

	plainText := "123-45-6789"
	ct, err := StructuredEncryptJwt(jwt, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("encrypt before reset: %v", err)
	}
	if pt, err := StructuredDecryptJwt(jwt, cfg, idpDatasetSSN, ct, nil); err != nil || pt != plainText {
		t.Fatalf("decrypt before reset: pt=%q err=%v", pt, err)
	}

	CloseJwt()

	ct, err = StructuredEncryptJwt(jwt, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("encrypt after reset: %v", err)
	}
	if pt, err := StructuredDecryptJwt(jwt, cfg, idpDatasetSSN, ct, nil); err != nil || pt != plainText {
		t.Fatalf("decrypt after reset: pt=%q err=%v", pt, err)
	}
}

// TestIdpMultipleJwt confirms three distinct users yield distinct identities and
// that ciphertext from one encryptor is decryptable by another (same dataset
// key). Requires RW, RO and WO users.
func TestIdpMultipleJwt(t *testing.T) {
	cfg := idpTestConfig(t)
	defer CloseJwt()

	jwtRw := idpJwt(t, cfg, envIdpUsername, envIdpPassword)
	jwtRo := idpJwt(t, cfg, envIdpRoUsername, envIdpRoPassword)
	jwtWo := idpJwt(t, cfg, envIdpWoUsername, envIdpWoPassword)

	if jwtRw == jwtRo || jwtRw == jwtWo || jwtRo == jwtWo {
		t.Fatal("expected three distinct JWTs")
	}

	jwtUser := func(jwt string) string {
		claims, err := parseJwt(jwt)
		if err != nil {
			t.Fatalf("parseJwt: %v", err)
		}
		if claims.Sub != "" {
			return claims.Sub
		}
		return claims.UniqueName
	}
	rw, ro, wo := jwtUser(jwtRw), jwtUser(jwtRo), jwtUser(jwtWo)
	if rw == ro || rw == wo || ro == wo {
		t.Errorf("expected three distinct identities, got %q %q %q", rw, ro, wo)
	}

	plainText := "123-45-6789"

	// Encrypt with the write-capable users; decrypt with the read-capable user.
	ctRw, err := StructuredEncryptJwt(jwtRw, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("encrypt (rw): %v", err)
	}
	ctWo, err := StructuredEncryptJwt(jwtWo, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("encrypt (wo): %v", err)
	}
	if ctRw != ctWo {
		t.Errorf("expected identical ciphertext across users, got %q vs %q", ctRw, ctWo)
	}

	pt, err := StructuredDecryptJwt(jwtRo, cfg, idpDatasetSSN, ctRw, nil)
	if err != nil {
		t.Fatalf("decrypt (ro): %v", err)
	}
	if pt != plainText {
		t.Errorf("decrypted %q, want %q", pt, plainText)
	}
}

// TestIdpWriteOnly confirms a write-only user can encrypt (and for-search) but
// not decrypt.
func TestIdpWriteOnly(t *testing.T) {
	if os.Getenv(envIdpPermissions) == "" {
		t.Skipf("permission-enforcement test skipped: set %s to run", envIdpPermissions)
	}
	cfg := idpTestConfig(t)
	defer CloseJwt()
	jwt := idpJwt(t, cfg, envIdpWoUsername, envIdpWoPassword)

	plainText := "123-45-6789"
	ct, err := StructuredEncryptJwt(jwt, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("write-only encrypt: %v", err)
	}

	cts, err := StructuredEncryptForSearchJwt(jwt, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("write-only for-search: %v", err)
	}
	if !contains(cts, ct) {
		t.Errorf("for-search result %v does not contain %q", cts, ct)
	}

	if _, err := StructuredDecryptJwt(jwt, cfg, idpDatasetSSN, ct, nil); err == nil {
		t.Error("expected write-only user to fail decrypting")
	}
}

// TestIdpReadOnly confirms a read-only user can decrypt but not encrypt.
func TestIdpReadOnly(t *testing.T) {
	if os.Getenv(envIdpPermissions) == "" {
		t.Skipf("permission-enforcement test skipped: set %s to run", envIdpPermissions)
	}
	cfg := idpTestConfig(t)
	defer CloseJwt()

	writeJwt := idpJwt(t, cfg, envIdpWoUsername, envIdpWoPassword)
	readJwt := idpJwt(t, cfg, envIdpRoUsername, envIdpRoPassword)

	plainText := "123-45-6789"
	ct, err := StructuredEncryptJwt(writeJwt, cfg, idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("write encrypt: %v", err)
	}

	pt, err := StructuredDecryptJwt(readJwt, cfg, idpDatasetSSN, ct, nil)
	if err != nil {
		t.Fatalf("read-only decrypt: %v", err)
	}
	if pt != plainText {
		t.Errorf("decrypted %q, want %q", pt, plainText)
	}

	if _, err := StructuredEncryptJwt(readJwt, cfg, idpDatasetSSN, plainText, nil); err == nil {
		t.Error("expected read-only user to fail encrypting")
	}
}

// TestIdpSelfSigned exercises the self-signed (self-managed) IDP flow against
// a live server: the SDK mints a short-lived RS256 token locally with the
// configured private key (self_sign_key), exchanges it at the SSO endpoint,
// and performs a structured encrypt/decrypt round trip. The server-side
// directory must be configured with the matching public key and a directory
// user whose username equals the identity.
func TestIdpSelfSigned(t *testing.T) {
	provider := os.Getenv(envIdpType)
	if !isSelfSignedProvider(provider) {
		t.Skipf("self-signed IDP test skipped: %s (%q) is not a self-signed provider", envIdpType, provider)
	}
	keyFile := os.Getenv(envIdpSelfSignKeyFile)
	if keyFile == "" {
		t.Skipf("self-signed IDP test skipped: %s not set", envIdpSelfSignKeyFile)
	}
	keyPem, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("reading %s: %v", keyFile, err)
	}
	identity := os.Getenv(envIdpUsername)
	if identity == "" {
		t.Skipf("self-signed IDP test skipped: %s not set", envIdpUsername)
	}

	cfgJson := fmt.Sprintf(`{
		"idp": {
			"provider": %q,
			"ubiq_customer_id": %q,
			"self_sign_key": %q
		}
	}`,
		provider,
		os.Getenv(envIdpCustomerId),
		string(keyPem),
	)
	cfg, err := NewConfigurationFromJson(cfgJson)
	if err != nil {
		t.Fatalf("building self-signed configuration: %v", err)
	}
	if server := os.Getenv(envIdpServer); server != "" {
		os.Setenv(credentialsHostEnvId, server)
	}

	creds, err := (&CredentialsParams{IdpUsername: identity, Config: &cfg}).Build()
	if err != nil {
		t.Fatalf("building self-signed credentials: %v", err)
	}

	enc, err := NewStructuredEncryption(creds)
	if err != nil {
		t.Fatalf("NewStructuredEncryption: %v", err)
	}
	defer enc.Close()
	dec, err := NewStructuredDecryption(creds)
	if err != nil {
		t.Fatalf("NewStructuredDecryption: %v", err)
	}
	defer dec.Close()

	plainText := "123-45-6789"
	ct, err := enc.Cipher(idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("self-signed encrypt: %v", err)
	}
	if ct == plainText {
		t.Error("ciphertext equals plaintext")
	}
	pt, err := dec.Cipher(idpDatasetSSN, ct, nil)
	if err != nil {
		t.Fatalf("self-signed decrypt: %v", err)
	}
	if pt != plainText {
		t.Errorf("decrypted %q, want %q", pt, plainText)
	}

	cts, err := enc.CipherForSearch(idpDatasetSSN, plainText, nil)
	if err != nil {
		t.Fatalf("self-signed for-search: %v", err)
	}
	if !contains(cts, ct) {
		t.Errorf("for-search result %v does not contain %q", cts, ct)
	}
}
