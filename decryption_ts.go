package ubiq

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// DecryptionTS is a thread-safe version of an Unstructured decryption object.
// It holds the context of a chunked decryption operation.
// Use NewDecryptionTS() to create/initialize an Decryption object.
//
// The caller should use the Begin(), Update()..., End() sequence of
// calls to decrypt data. When decryption is complete, the caller
// should call Close().
//
// To maintain thread safety, Session data unique to the current
// decryption will be returned as part of each call in the sequence
// and need passed in as your data is handled.
type DecryptionTS struct {
	client httpClient
	host   string

	creds  *Credentials
	config *Configuration
	cache  *cache

	srsa string

	tracking trackingContext
}

// Holds all the stateful information associated with doing
// a Decryption operation. This should be used alongside any data
// and not used with irrelevant data.
type DecryptionSession struct {
	key decryptionKey

	cipher *cipher

	buf []byte
}

// request that the server decrypt a data key associated with a cipher text.
// this opens a new "session", meaning that the key can be reused if
// the next cipher text decrypted uses the same data key
func (d *DecryptionTS) initializeSession(session *DecryptionSession, edk []byte, algo int) error {
	var rsp *http.Response
	var err error

	var keyFromCache decryptionKey
	var usingCachedKey bool

	cacheKey := getUnstructuredCacheKey(edk, algo)

	if d.config.KeyCaching.Unstructured {
		keyFromCache, err = d.cache.readUnstructuredKey(cacheKey)
		if err != nil {
			if !errors.Is(err, ErrNotInCache) {
				return err
			}
		}
		usingCachedKey = len(keyFromCache.Epk) > 0
	}

	if !usingCachedKey || err != nil {
		if d.config.Logging.Verbose {
			fmt.Fprintf(os.Stdout, "****** PERFORMING EXPENSIVE CALL ----- fetchDecryptKey \n")
		}
		endp := d.host
		endp += "/api/v0/decryption/key"
		request := newDecryptionRequest{
			EDK: base64.StdEncoding.EncodeToString(edk),
		}

		isIdp, _ := d.creds.isIdp()
		if isIdp {
			// IDP mode requires passing the idp cert to the server
			d.creds.renewIdpCert()
			request.PayloadCert = d.creds.idpBase64Cert
		}

		body, _ := json.Marshal(request)
		rsp, err = d.client.Post(
			endp, "application/json", bytes.NewReader(body))
		if rsp != nil {
			defer rsp.Body.Close()
		}
		if err == nil {
			if rsp.StatusCode == http.StatusOK {
				var nd newDecryptionResponse

				err = json.NewDecoder(rsp.Body).Decode(&nd)
				if err == nil {
					session.key.Session = nd.EncryptionSession
					session.key.Fingerprint = nd.KeyFingerprint
					session.key.Enc = edk
					session.key.Uses = 0
					session.key.Algo, err = getAlgorithmById(algo)
					session.key.AlgorithmId = algo

					session.key.Wdk = nd.WDK
					if isIdp {
						// IDP mode has a local private key, need to override that key since nothing will be returned from server
						session.key.Epk = d.creds.idpEncryptedPrivateKey
					} else {
						session.key.Epk = nd.EPK
					}
				}
			} else {
				err = errors.New(
					"unexpected http response " + rsp.Status)
				return err
			}
		}

		if d.config.KeyCaching.Unstructured && d.config.KeyCaching.Encrypt {
			d.cache.updateUnstructuredKey(cacheKey, session.key)
		}
	} else {
		session.key.AlgorithmId = keyFromCache.AlgorithmId
		session.key.Algo, err = getAlgorithmById(keyFromCache.AlgorithmId)
		session.key.Raw = keyFromCache.Raw
		session.key.Wdk = keyFromCache.Wdk
		session.key.Epk = keyFromCache.Epk
		session.key.Enc = edk
		session.key.Fingerprint = keyFromCache.Fingerprint
		session.key.Uses = keyFromCache.Uses
		session.key.Session = keyFromCache.Session
	}

	if session.key.Raw == nil {
		session.key.Raw, err = unwrapDataKey(
			session.key.Wdk, session.key.Epk, d.srsa)
	}

	if d.config.KeyCaching.Unstructured && !d.config.KeyCaching.Encrypt && !usingCachedKey {
		d.cache.updateUnstructuredKey(cacheKey, session.key)
	}

	return err
}

// NewDecryption creates a new thread-safe Decryption object
func NewDecryptionTS(c Credentials) (*DecryptionTS, error) {
	dec := DecryptionTS{}
	var err error

	dec.client = newHttpClient(c)
	dec.host, _ = c.host()

	dec.srsa, _ = c.srsa()

	dec.tracking = newTrackingContext(dec.client, dec.host, c.config)

	dec.config = c.config
	dec.cache = &c.cache
	dec.creds = &c

	return &dec, err
}

// Begin starts a new decryption operation. Returns a new
// DecryptionSession object. This object contains the state of
// the current decryption in process and should not be used across
// multiple decryptions.
func (d *DecryptionTS) Begin() ([]byte, *DecryptionSession) {
	var session DecryptionSession

	return nil, &session
}

// Update passes cipher text into the Decryption object for decryption.
// Depending on how much data has been previously processed by Update
// and how much is passed by the current call, the function may or may
// not return any data.
//
// error is nil on success and the slice may or may not contain plain
// text. If error is non-nil, the caller may call End() (which may also
// return an error) to reset the Decryption object for a new decryption.
//
// Note that even though plain text may be returned by this function, it
// should not be trusted until End() has returned successfully.
func (d *DecryptionTS) Update(session *DecryptionSession, ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	var err error

	// incoming data goes into the internal buffer.
	// data is sliced off the front as it is used/decrypted.
	session.buf = append(session.buf, ciphertext...)

	// cipher is nil until we have a complete, valid header
	// that can be decoded to obtain the key, iv, and algorithm
	if session.cipher == nil {
		hdrlen := headerValid(session.buf)

		if hdrlen < 0 {
			// header is invalid and can't be parsed/recovered
			err = errors.New("invalid encryption header")
		} else if hdrlen > 0 {
			// header is valid and contains `hdrlen` bytes
			hdr := newHeader(session.buf)
			if hdr.version != 0 {
				err = errors.New(
					"unsupported encryption header")
			}

			if err == nil {
				// if a session exists, but it has a different
				// key, get rid of it
				if len(session.key.Session) > 0 &&
					!bytes.Equal(
						session.key.Enc, hdr.v0.key) {
					err = errors.New("Invalid session provided.")
				}

				// if no session exists, create a new one
				if len(session.key.Session) == 0 {
					err = d.initializeSession(session,
						hdr.v0.key, int(hdr.v0.algo))

					if err != nil {
						return plaintext, err
					}
				}
			}

			// at this point, either err != nil or
			// a valid session exists (either because it can
			// be reused or because a new one was created)
			if err == nil {
				var c cipher

				// if the header flags indicate that the
				// header is authenticated, pass it to the
				// cipher creation function
				if (hdr.v0.flags & headerV0FlagAAD) != 0 {
					c, err = session.key.Algo.newCipher(
						session.key.Raw, hdr.v0.iv,
						session.buf[:hdrlen])
				} else {
					c, err = session.key.Algo.newCipher(
						session.key.Raw, hdr.v0.iv)
				}

				if err == nil {
					d.tracking.AddEvent(
						d.client.papi, "", "",
						trackingActionDecrypt,
						1, 0)
					// all is well, slice off the header
					session.cipher = &c
					session.key.Uses++
					session.buf = session.buf[hdrlen:]
				}
			}
		}
		// else
		//   it can't be determined yet if header is valid.
		//   more data is necessary
	}

	if session.cipher != nil {
		// determine how much data is in the buffer,
		// being careful to always leave enough data in
		// the buffer to act as the authentication tag
		sz := len(session.buf) - session.key.Algo.len.tag
		if sz > 0 {
			// decrypt whatever data is not part of the
			// data reserved for the tag, and slice it
			// off the internal buffer
			plaintext = session.cipher.decipher(session.buf[:sz])
			session.buf = session.buf[sz:]
		}
	}

	return plaintext, err
}

// End completes the decryption of a cipher text message. For certain
// algorithms, message authenticity checks will be performed, and any
// remaining plain text will be returned.
//
// error is nil upon success and the byte slice may or may not contain
// any remaining plain text. If error is non-nil, any previously decrypted
// plain text should be discarded.
func (d *DecryptionTS) End(session *DecryptionSession) ([]byte, error) {
	var res []byte
	var err error

	if session.cipher != nil {
		sz := len(session.buf) - session.key.Algo.len.tag

		if sz > 0 {
			// once the cipher has been created, the Update
			// function never leaves more that a tag's worth
			// of data in the buffer, so this code shouldn't
			// even be reachable
			panic("ubiq/decryption: too much data for tag")
		} else if sz < 0 {
			// this can only happen if Update was never even
			// provided tag's worth of cipher text
			err = errors.New("not enough data for tag")
		} else /* sz == 0 */ {
			// either the tag length is 0, which means that
			// there is no more data in the buffer, or the
			// number of bytes in the buffer is equal to
			// the size of the tag

			if session.key.Algo.len.tag == 0 {
				// pass nil to indicate no tag
				res, err = session.cipher.close(nil)
			} else {
				res, err = session.cipher.close(session.buf)
			}
		}

		session.cipher = nil
		session.buf = nil
	}

	return res, err
}

// Close cleans up the Decryption object and resets it to its default values.
// An error returned by this function is a result of a miscommunication with
// the server, and the object is reset regardless.
func (d *DecryptionTS) Close() {
	d.tracking.Close()
	*d = DecryptionTS{}
}

// Attach metadata to usage information reported by the application.
func (d *DecryptionTS) AddUserDefinedMetadata(data string) error {
	return d.tracking.AddUserDefinedMetadata(data)
}
