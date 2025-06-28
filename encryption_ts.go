package ubiq

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

// EncryptionTS is a thread-safe version of an Encryption object.
// It holds the context of a chunked encryption operation.
// Use NewEncryptionTS() to create/initialize an Encryption object.
//
// After creating an Encryption object, the caller should use the
// Begin(), Update()..., End() sequence of calls for as many separate
// encryptions need to be performed using the key associated with the
// Encryption object. When all encryptions are complete, call Close().
//
// To maintain thread safety, Session data unique to the current
// encryption will be returned as part of each call in the sequence
// and need passed in as your data is handled.
type EncryptionTS struct {
	client httpClient
	host   string

	session  string
	fragment bool

	key struct {
		raw, enc    []byte
		fingerprint string
		uses        struct {
			max, cur uint
		}
	}

	algo algorithm

	tracking trackingContext
}

// Contains any stateful information associated with doing a chunked
// encryption operation. Should not be used across threads or different
// encryptions.
type EncryptionSession struct {
	cipher *cipher
}

// init initializes the EncryptionTS object using the encryption response
// received from the server containing the wrapped data key, algorithm,
// session, etc.
func (e *EncryptionTS) init(rsp newEncryptionResponse, srsa string) error {
	var err error

	e.session = rsp.EncryptionSession
	e.fragment = rsp.SecurityModel.Fragmentation

	e.key.fingerprint = rsp.KeyFingerprint
	e.key.uses.max = uint(rsp.MaxUses)
	e.key.uses.cur = 0

	e.key.enc, err = base64.StdEncoding.DecodeString(rsp.EDK)
	if err == nil {
		e.key.raw, err = unwrapDataKey(rsp.WDK, rsp.EPK, srsa)
	}

	if err == nil {
		e.algo, err = getAlgorithmByName(rsp.SecurityModel.Algorithm)
	}

	return err
}

// NewEncryptionTS creates a new thread-safe Encryption object with a
// new key that can be used, at most, the specified number of times.
// (The actual number may be less, depending on security settings at
// the server.)
func NewEncryptionTS(c Credentials, uses uint) (*EncryptionTS, error) {
	enc := EncryptionTS{}

	enc.client = newHttpClient(c)
	enc.host, _ = c.host()

	endp := enc.host + "/api/v0/encryption/key"
	request := newEncryptionRequest{Uses: uses}

	isIdp, _ := c.isIdp()
	if isIdp {
		// IDP mode requires passing the idp cert to the server
		c.renewIdpCert()
		request.PayloadCert = c.idpBase64Cert
	}

	body, _ := json.Marshal(request)
	if c.config.Logging.Verbose {
		fmt.Fprintf(os.Stdout, "****** PERFORMING EXPENSIVE CALL ----- fetchEncryptKey \n")
	}
	rsp, err := enc.client.Post(endp, "application/json", bytes.NewReader(body))

	if rsp != nil {
		defer rsp.Body.Close()
	}

	if err == nil {
		var ne newEncryptionResponse

		if rsp.StatusCode == http.StatusCreated {
			err = json.NewDecoder(rsp.Body).Decode(&ne)
		} else {
			errMsg, _ := io.ReadAll(rsp.Body)
			err = errors.New("unexpected response: " + string(errMsg))
		}

		if err == nil {
			srsa, _ := c.srsa()
			if isIdp {
				// IDP mode has a local private key, need to override that key since nothing will be returned from server
				ne.EPK = c.idpEncryptedPrivateKey
			}
			err = enc.init(ne, srsa)
		}
	}

	if err == nil {
		enc.tracking = newTrackingContext(enc.client, enc.host, c.config)
	} else {
		enc = EncryptionTS{}
	}

	return &enc, err
}

// Begin starts a new encryption operation. The Encryption object
// must be newly created by the NewEncryption object, or the previous
// encryption performed by it must have been ended with the End()
// function.
//
// error is nil upon success. Information about the encryption is
// returned on success and must be treated as part of the cipher text
func (e *EncryptionTS) Begin() ([]byte, *EncryptionSession, error) {
	var hdr []byte
	var h header
	var err error

	var session EncryptionSession

	if session.cipher != nil {
		return nil, &session, errors.New("encryption already in progress")
	}

	e.tracking.AddEvent(
		e.client.papi, "", "",
		trackingActionEncrypt,
		1, 0)

	h.version = 0
	h.v0.flags = 0
	if e.algo.aad {
		// if the algorithm supports additional authenticated
		// data, then authenticate the header
		h.v0.flags |= headerV0FlagAAD
	}
	h.v0.algo = uint8(e.algo.id)
	h.v0.iv = make([]byte, e.algo.len.iv)
	h.v0.key = e.key.enc

	_, err = rand.Read(h.v0.iv)
	if err == nil {
		var c cipher

		hdr = h.serialize()

		if e.algo.aad {
			c, err = e.algo.newCipher(
				e.key.raw, h.v0.iv, hdr)
		} else {
			c, err = e.algo.newCipher(
				e.key.raw, h.v0.iv)
		}
		if err == nil {
			session.cipher = &c
			e.key.uses.cur++
		}
	}

	return hdr, &session, err
}

// Update passes plain text into the Encryption object for encryption.
// Depending on how much data has been previously processed by Update
// and how much is passed by the current call, the function may or may
// not return any data.
//
// error is nil on success and the slice may or may not contain cipher text.
func (e *EncryptionTS) Update(session *EncryptionSession, plaintext []byte) ([]byte, error) {
	return session.cipher.encipher(plaintext), nil
}

// End completes the encryption of a plain text message. For certain
// algorithms, message authenticity checks will be performed, and any
// remaining plain text will be returned.
//
// error is nil upon success and the byte slice may or may not contain
// any remaining plain text. If error is non-nil, any previously decrypted
// plain text should be discarded.
func (e *EncryptionTS) End(session *EncryptionSession) ([]byte, error) {
	res, err := session.cipher.close()
	session.cipher = nil
	return res, err
}

// Close cleans up the Encryption object and resets it to its default values.
// An error returned by this function is a result of a miscommunication with
// the server, and the object is reset regardless.
func (e *EncryptionTS) Close() error {
	e.tracking.Close()
	*e = EncryptionTS{}

	return nil
}

// Attach metadata to usage information reported by the application.
func (e *EncryptionTS) AddUserDefinedMetadata(data string) error {
	return e.tracking.AddUserDefinedMetadata(data)
}
