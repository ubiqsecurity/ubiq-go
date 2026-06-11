package ubiq

import (
	"sync"
	"time"
)

// The functions in this file provide a JWT-oriented convenience layer over
// structured encryption for multi-tenant callers (for example a server that
// already holds many users' JWT access tokens). Each distinct JWT identity is
// resolved to a set of IDP credentials once and the resulting structured
// encryption/decryption objects are cached and reused.
//
// Caveats:
//   - The cached objects are process-global and are never Close()d, so their
//     tracking events flush at process exit. This matches the multi-tenant
//     server use case where the process is long lived.
//   - A cached object is shared across goroutines for the same identity; the
//     mutex below only guards cache lookup/creation and the stored-token
//     refresh, not the encryption work itself.
var (
	jwtStructMu sync.Mutex
	jwtObjects  = map[string]*jwtEntry{}
)

// jwtEntry holds everything cached for one JWT identity. The enc and dec
// objects are built lazily from the shared credentials, so both read and
// write the same underlying key/dataset cache.
type jwtEntry struct {
	creds Credentials
	// lastJwt is the most recently presented raw token. It only exists so
	// the next cert renewal uses a fresh token instead of the one the entry
	// was built with; presenting a known token never touches the network.
	lastJwt string
	enc     *StructuredEncryption // nil until the first encrypt call
	dec     *StructuredDecryption // nil until the first decrypt call
}

// jwtCacheKey resolves the identity used to cache objects for a JWT. It prefers
// the subject claim, matching how the multi-tenant flow keys users.
func jwtCacheKey(jwt string) (string, error) {
	claims, err := parseJwt(jwt)
	if err != nil {
		return "", err
	}
	name := claims.Sub
	if name == "" {
		name = claims.UniqueName
	}
	if name == "" {
		name = claims.Email
	}
	return name, nil
}

// jwtEntryLocked returns (building and caching if necessary) the cache entry
// for a JWT identity. Callers must hold jwtStructMu.
func jwtEntryLocked(key, jwt string, cfg *Configuration) (*jwtEntry, error) {
	if entry, ok := jwtObjects[key]; ok {
		if jwt != entry.lastJwt {
			entry.lastJwt = jwt
			entry.creds.setIdpJwt(jwt)
		}
		return entry, nil
	}
	creds, err := (&CredentialsParams{IdpJwt: jwt, Config: cfg}).Build()
	if err != nil {
		return nil, err
	}
	entry := &jwtEntry{creds: creds, lastJwt: jwt}
	jwtObjects[key] = entry
	return entry, nil
}

func getStructEncByJwt(jwt string, cfg *Configuration) (*StructuredEncryption, error) {
	key, err := jwtCacheKey(jwt)
	if err != nil {
		return nil, err
	}

	jwtStructMu.Lock()
	defer jwtStructMu.Unlock()

	entry, err := jwtEntryLocked(key, jwt, cfg)
	if err != nil {
		return nil, err
	}
	if entry.enc == nil {
		enc, err := NewStructuredEncryption(entry.creds)
		if err != nil {
			return nil, err
		}
		entry.enc = enc
	}
	return entry.enc, nil
}

func getStructDecByJwt(jwt string, cfg *Configuration) (*StructuredDecryption, error) {
	key, err := jwtCacheKey(jwt)
	if err != nil {
		return nil, err
	}

	jwtStructMu.Lock()
	defer jwtStructMu.Unlock()

	entry, err := jwtEntryLocked(key, jwt, cfg)
	if err != nil {
		return nil, err
	}
	if entry.dec == nil {
		dec, err := NewStructuredDecryption(entry.creds)
		if err != nil {
			return nil, err
		}
		entry.dec = dec
	}
	return entry.dec, nil
}

// CloseJwt closes and discards every cached JWT-keyed encryption and decryption
// object, flushing their tracking events, and clears the cached credentials.
// Subsequent JWT calls rebuild the objects on demand. It is the Go equivalent
// of the Java SDK's closeJwt().
func CloseJwt() {
	jwtStructMu.Lock()
	defer jwtStructMu.Unlock()

	for _, entry := range jwtObjects {
		if entry.enc != nil {
			entry.enc.Close()
		}
		if entry.dec != nil {
			entry.dec.Close()
		}
	}
	jwtObjects = map[string]*jwtEntry{}
}

// String

// StructuredEncryptJwt encrypts a string using the IDP credentials identified
// by the supplied JWT access token.
func StructuredEncryptJwt(jwt string, cfg *Configuration, dataset, pt string, twk []byte) (string, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return "", err
	}
	return enc.Cipher(dataset, pt, twk)
}

// StructuredDecryptJwt decrypts a string using the IDP credentials identified
// by the supplied JWT access token.
func StructuredDecryptJwt(jwt string, cfg *Configuration, dataset, ct string, twk []byte) (string, error) {
	dec, err := getStructDecByJwt(jwt, cfg)
	if err != nil {
		return "", err
	}
	return dec.Cipher(dataset, ct, twk)
}

// StructuredEncryptForSearchJwt returns the ciphertext for every key version of
// a dataset, using the IDP credentials identified by the supplied JWT.
func StructuredEncryptForSearchJwt(jwt string, cfg *Configuration, dataset, pt string, twk []byte) ([]string, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return nil, err
	}
	return enc.CipherForSearch(dataset, pt, twk)
}

// Int32

func StructuredEncryptInt32Jwt(jwt string, cfg *Configuration, dataset string, pt int32, twk []byte) (int32, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return 0, err
	}
	return enc.CipherInt32(dataset, pt, twk)
}

func StructuredDecryptInt32Jwt(jwt string, cfg *Configuration, dataset string, ct int32, twk []byte) (int32, error) {
	dec, err := getStructDecByJwt(jwt, cfg)
	if err != nil {
		return 0, err
	}
	return dec.DecipherInt32(dataset, ct, twk)
}

func StructuredEncryptInt32ForSearchJwt(jwt string, cfg *Configuration, dataset string, pt int32, twk []byte) ([]int32, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return nil, err
	}
	return enc.CipherInt32ForSearch(dataset, pt, twk)
}

// Int64

func StructuredEncryptInt64Jwt(jwt string, cfg *Configuration, dataset string, pt int64, twk []byte) (int64, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return 0, err
	}
	return enc.CipherInt64(dataset, pt, twk)
}

func StructuredDecryptInt64Jwt(jwt string, cfg *Configuration, dataset string, ct int64, twk []byte) (int64, error) {
	dec, err := getStructDecByJwt(jwt, cfg)
	if err != nil {
		return 0, err
	}
	return dec.DecipherInt64(dataset, ct, twk)
}

func StructuredEncryptInt64ForSearchJwt(jwt string, cfg *Configuration, dataset string, pt int64, twk []byte) ([]int64, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return nil, err
	}
	return enc.CipherInt64ForSearch(dataset, pt, twk)
}

// Date

func StructuredEncryptDateJwt(jwt string, cfg *Configuration, dataset string, pt time.Time, twk []byte) (time.Time, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return time.Time{}, err
	}
	return enc.CipherDate(dataset, pt, twk)
}

func StructuredDecryptDateJwt(jwt string, cfg *Configuration, dataset string, ct time.Time, twk []byte) (time.Time, error) {
	dec, err := getStructDecByJwt(jwt, cfg)
	if err != nil {
		return time.Time{}, err
	}
	return dec.DecipherDate(dataset, ct, twk)
}

func StructuredEncryptDateForSearchJwt(jwt string, cfg *Configuration, dataset string, pt time.Time, twk []byte) ([]time.Time, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return nil, err
	}
	return enc.CipherDateForSearch(dataset, pt, twk)
}

// DateTime

func StructuredEncryptDateTimeJwt(jwt string, cfg *Configuration, dataset string, pt time.Time, twk []byte) (time.Time, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return time.Time{}, err
	}
	return enc.CipherDateTime(dataset, pt, twk)
}

func StructuredDecryptDateTimeJwt(jwt string, cfg *Configuration, dataset string, ct time.Time, twk []byte) (time.Time, error) {
	dec, err := getStructDecByJwt(jwt, cfg)
	if err != nil {
		return time.Time{}, err
	}
	return dec.DecipherDateTime(dataset, ct, twk)
}

func StructuredEncryptDateTimeForSearchJwt(jwt string, cfg *Configuration, dataset string, pt time.Time, twk []byte) ([]time.Time, error) {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return nil, err
	}
	return enc.CipherDateTimeForSearch(dataset, pt, twk)
}

// StructuredLoadCacheJwt pre-loads dataset definitions and keys for the
// supplied datasets using the IDP credentials identified by the JWT. The
// encryption and decryption objects for an identity share the same underlying
// cache, so loading once serves both.
func StructuredLoadCacheJwt(jwt string, cfg *Configuration, datasets []string) error {
	enc, err := getStructEncByJwt(jwt, cfg)
	if err != nil {
		return err
	}
	return enc.LoadCache(datasets)
}
