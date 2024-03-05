package ubiq

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
)

type updateDecryptionRequest struct {
	Uses uint `json:"uses"`
}

type newDecryptionResponse struct {
	EPK               string `json:"encrypted_private_key"`
	EncryptionSession string `json:"encryption_session"`
	KeyFingerprint    string `json:"key_fingerprint"`
	WDK               string `json:"wrapped_data_key"`
}

type newDecryptionRequest struct {
	EDK string `json:"encrypted_data_key"`
}

// Decryption holds the context of a piecewise decryption operation.
// Use NewDecryption() to create/initialize an Decryption object.
//
// The caller should use the Begin(), Update()..., End() sequence of
// calls to decrypt data. When decryption is complete, the caller
// should call Close().
type Decryption struct {
	client httpClient
	host   string

	session, srsa string

	key struct {
		raw, enc    []byte
		fingerprint string
		uses        uint
	}

	algo   algorithm
	cipher *cipher

	buf []byte

	tracking trackingContext
}

func (d *Decryption) resetSession() error {
	d.session = ""

	d.key.raw = nil
	d.key.enc = nil
	d.key.fingerprint = ""
	d.key.uses = 0

	d.algo = algorithm{}
	d.cipher = nil

	d.buf = nil

	return nil
}

// request that the server decrypt a data key associated with a cipher text.
// this opens a new "session", meaning that the key can be reused if
// the next cipher text decrypted uses the same data key
func (d *Decryption) newSession(edk []byte, algo int) error {
	var rsp *http.Response
	var err error

	endp := d.host
	endp += "/api/v0/decryption/key"

	body, _ := json.Marshal(newDecryptionRequest{
		EDK: base64.StdEncoding.EncodeToString(edk)})
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
				d.key.raw, err = unwrapDataKey(
					nd.WDK, nd.EPK, d.srsa)
			}
			if err == nil {
				d.session = nd.EncryptionSession
				d.key.fingerprint = nd.KeyFingerprint
				d.key.enc = edk
				d.key.uses = 0
				d.algo, err = getAlgorithmById(algo)
			}
		} else {
			err = errors.New(
				"unexpected http response " + rsp.Status)
		}
	}

	return err
}

// NewDecryption creates a new Decryption object which holds the context
// of a decryption while it is in process.
func NewDecryption(c Credentials) (*Decryption, error) {
	dec := Decryption{}

	dec.client = newHttpClient(c)
	dec.host, _ = c.host()

	dec.srsa, _ = c.srsa()

	dec.tracking = newTrackingContext(dec.client, dec.host)

	return &dec, nil
}

// Begin starts a new decryption operation. The Decryption object
// must be newly created by the NewDecryption object, or the previous
// decryption performed by it must have been ended with the End()
// function.
//
// error is nil upon success. No data is returned by this call; however,
// a slice is returned to maintain the same function signature as the
// corresponding Encryption call.
func (d *Decryption) Begin() ([]byte, error) {
	var err error

	if d.cipher != nil {
		err = errors.New("decryption already in progress")
	}

	return nil, err
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
func (d *Decryption) Update(ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	var err error

	// incoming data goes into the internal buffer.
	// data is sliced off the front as it is used/decrypted.
	d.buf = append(d.buf, ciphertext...)

	// cipher is nil until we have a complete, valid header
	// that can be decoded to obtain the key, iv, and algorithm
	if d.cipher == nil {
		hdrlen := headerValid(d.buf)

		if hdrlen < 0 {
			// header is invalid and can't be parsed/recovered
			err = errors.New("invalid encryption header")
		} else if hdrlen > 0 {
			// header is valid and contains `hdrlen` bytes
			hdr := newHeader(d.buf)
			if hdr.version != 0 {
				err = errors.New(
					"unsupported encryption header")
			}

			if err == nil {
				// if a session exists, but it has a different
				// key, get rid of it
				if len(d.session) > 0 &&
					!bytes.Equal(
						d.key.enc, hdr.v0.key) {
					d.resetSession()
				}

				// if no session exists, create a new one
				if len(d.session) == 0 {
					err = d.newSession(
						hdr.v0.key, int(hdr.v0.algo))
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
					c, err = d.algo.newCipher(
						d.key.raw, hdr.v0.iv,
						d.buf[:hdrlen])
				} else {
					c, err = d.algo.newCipher(
						d.key.raw, hdr.v0.iv)
				}

				if err == nil {
					d.tracking.AddEvent(
						d.client.papi, "", "",
						trackingActionDecrypt,
						1, 0)
					// all is well, slice off the header
					d.cipher = &c
					d.key.uses++
					d.buf = d.buf[hdrlen:]
				}
			}
		}
		// else
		//   it can't be determined yet if header is valid.
		//   more data is necessary
	}

	if d.cipher != nil {
		// determine how much data is in the buffer,
		// being careful to always leave enough data in
		// the buffer to act as the authentication tag
		sz := len(d.buf) - d.algo.len.tag
		if sz > 0 {
			// decrypt whatever data is not part of the
			// data reserved for the tag, and slice it
			// off the internal buffer
			plaintext = d.cipher.decipher(d.buf[:sz])
			d.buf = d.buf[sz:]
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
func (d *Decryption) End() ([]byte, error) {
	var res []byte
	var err error

	if d.cipher != nil {
		sz := len(d.buf) - d.algo.len.tag

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

			if d.algo.len.tag == 0 {
				// pass nil to indicate no tag
				res, err = d.cipher.close(nil)
			} else {
				res, err = d.cipher.close(d.buf)
			}
		}

		d.cipher = nil
		d.buf = nil
	}

	return res, err
}

// Close cleans up the Decryption object and resets it to its default values.
// An error returned by this function is a result of a miscommunication with
// the server, and the object is reset regardless.
func (d *Decryption) Close() error {
	err := d.resetSession()
	d.tracking.Close()
	*d = Decryption{}
	return err
}

// Decrypt decrypts a single ciphertext message. The credentials
// must be associated with the key used to encrypt the cipher text.
//
// Upon success, error is nil, and the plain text is returned. If an
// error occurs, it will be indicated by the error return value.
func Decrypt(c Credentials, ciphertext []byte) ([]byte, error) {
	var err error
	var plaintext, tmp []byte

	dec, err := NewDecryption(c)
	if dec != nil {
		defer dec.Close()
	}
	if err != nil {
		return nil, err
	}

	dec.Begin()
	plaintext, err = dec.Update(ciphertext)
	if err != nil {
		return nil, err
	}

	tmp, err = dec.End()
	if err != nil {
		return nil, err
	}

	return append(plaintext, tmp...), nil
}
