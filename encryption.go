package ubiq

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"

	"github.com/youmark/pkcs8"
)

type newEncryptionResponse struct {
	EPK               string `json:"encrypted_private_key"`
	EncryptionSession string `json:"encryption_session"`
	KeyFingerprint    string `json:"key_fingerprint"`
	WDK               string `json:"wrapped_data_key"`
	EDK               string `json:"encrypted_data_key"`
	MaxUses           int    `json:"max_uses"`
	SecurityModel     struct {
		Algorithm     string `json:"algorithm"`
		Fragmentation bool   `json:"enable_data_fragmentation"`
	} `json:"security_model"`
}

type newEncryptionRequest struct {
	Uses        uint   `json:"uses"`
	PayloadCert string `json:"payload_cert"`
}

// Encryption holds the context of a chunked encryption operation.
// Use NewEncryption() to create/initialize an Encryption object.
//
// After creating an Encryption object, the caller should use the
// Begin(), Update()..., End() sequence of calls for as many separate
// encryptions need to be performed using the key associated with the
// Encryption object. When all encryptions are complete, call Close().
type Encryption struct {
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

	algo   algorithm
	cipher *cipher

	tracking trackingContext
}

func decryptPrivateKey(epk, srsa string) (pk *rsa.PrivateKey, err error) {
	block, rem := pem.Decode([]byte(epk))
	if len(rem) == 0 {
		pk, err = pkcs8.ParsePKCS8PrivateKeyRSA(
			block.Bytes, []byte(srsa))
	} else {
		err = errors.New("unrecognized key format")
	}

	return
}

func decryptDataKey(wdk string, pk *rsa.PrivateKey) ([]byte, error) {
	wdkbytes, err := base64.StdEncoding.DecodeString(wdk)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(sha1.New(), nil, pk, wdkbytes, nil)
}

func unwrapDataKey(wdk, epk, srsa string) ([]byte, error) {
	pk, err := decryptPrivateKey(epk, srsa)
	if err != nil {
		return nil, err
	}

	return decryptDataKey(wdk, pk)
}

// init initializes the Encryption object using the encryption response
// received from the server containing the wrapped data key, algorithm,
// session, etc.
func (e *Encryption) init(rsp newEncryptionResponse, srsa string) error {
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

// NewEncryption creates a new Encryption object with a new key that can
// be used, at most, the specified number of times. (The actual number
// may be less, depending on security settings at the server.)
func NewEncryption(c Credentials, uses uint) (*Encryption, error) {
	enc := Encryption{}

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
		enc = Encryption{}
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
func (e *Encryption) Begin() ([]byte, error) {
	var hdr []byte
	var h header
	var err error

	if e.cipher != nil {
		return nil, errors.New("encryption already in progress")
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
			e.cipher = &c
			e.key.uses.cur++
		}
	}

	return hdr, err
}

// Update passes plain text into the Encryption object for encryption.
// Depending on how much data has been previously processed by Update
// and how much is passed by the current call, the function may or may
// not return any data.
//
// error is nil on success and the slice may or may not contain cipher text.
func (e *Encryption) Update(plaintext []byte) ([]byte, error) {
	return e.cipher.encipher(plaintext), nil
}

// End completes the encryption of a plain text message. For certain
// algorithms, message authenticity checks will be performed, and any
// remaining plain text will be returned.
//
// error is nil upon success and the byte slice may or may not contain
// any remaining plain text. If error is non-nil, any previously decrypted
// plain text should be discarded.
func (e *Encryption) End() ([]byte, error) {
	res, err := e.cipher.close()
	e.cipher = nil
	return res, err
}

// Close cleans up the Encryption object and resets it to its default values.
// An error returned by this function is a result of a miscommunication with
// the server, and the object is reset regardless.
func (e *Encryption) Close() error {
	e.tracking.Close()
	*e = Encryption{}

	return nil
}

// Attach metadata to usage information reported by the application.
func (e *Encryption) AddUserDefinedMetadata(data string) error {
	return e.tracking.AddUserDefinedMetadata(data)
}

// Encrypt encrypts a single plain text message using a new key
// and the algorithm associated with the specified credentials.
//
// Upon success, error is nil, and the cipher text is returned. If
// an error occurs, it will be indicated by the error return value.
func Encrypt(c Credentials, plaintext []byte) ([]byte, error) {
	var err error
	var ciphertext, tmp []byte

	enc, err := NewEncryption(c, 1)
	if enc != nil {
		defer enc.Close()
	}
	if err != nil {
		return nil, err
	}

	ciphertext, err = enc.Begin()
	if err != nil {
		return nil, err
	}

	tmp, _ = enc.Update(plaintext)
	ciphertext = append(ciphertext, tmp...)

	tmp, _ = enc.End()

	return append(ciphertext, tmp...), nil
}
