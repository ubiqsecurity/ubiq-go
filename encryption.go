// Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains the property
// of Ubiq Security, Inc. The intellectual and technical concepts contained
// herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
// covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this
// information or reproduction of this material is strictly forbidden
// unless prior written permission is obtained from Ubiq Security, Inc.
//
// Your use of the software is expressly conditioned upon the terms
// and conditions available at:
//
//     https://ubiqsecurity.com/legal

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
	"github.com/youmark/pkcs8"
	"net/http"
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
	Uses uint `json:"uses"`
}

type updateEncryptionRequest struct {
	Requested uint `json:"requested"`
	Actual    uint `json:"actual"`
}

// Encryption holds the context of a piecewise encryption operation.
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
}

func unwrapDataKey(wdk, epk, srsa string) ([]byte, error) {
	var err error
	var pk *rsa.PrivateKey
	var dk []byte

	block, rem := pem.Decode([]byte(epk))
	if len(rem) == 0 {
		pk, err = pkcs8.ParsePKCS8PrivateKeyRSA(
			block.Bytes, []byte(srsa))
	} else {
		err = errors.New("unrecognized key format")
	}

	if err == nil {
		var wdkbytes []byte

		wdkbytes, err = base64.StdEncoding.DecodeString(wdk)
		if err == nil {
			dk, err = rsa.DecryptOAEP(
				sha1.New(), nil, pk, wdkbytes, nil)
		}
	}

	return dk, err
}

// init initializes the Encryption object using the encryption response
// received from the server containing the wrapped data key, algorithm,
// session, etc.
func (this *Encryption) init(rsp newEncryptionResponse, srsa string) error {
	var err error

	this.session = rsp.EncryptionSession
	this.fragment = rsp.SecurityModel.Fragmentation

	this.key.fingerprint = rsp.KeyFingerprint
	this.key.uses.max = uint(rsp.MaxUses)
	this.key.uses.cur = 0

	this.key.enc, err = base64.StdEncoding.DecodeString(rsp.EDK)
	if err == nil {
		this.key.raw, err = unwrapDataKey(rsp.WDK, rsp.EPK, srsa)
	}

	if err == nil {
		this.algo, err =
			getAlgorithmByName(rsp.SecurityModel.Algorithm)
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

	body, _ := json.Marshal(newEncryptionRequest{Uses: uses})
	rsp, err := enc.client.Post(
		endp, "application/json", bytes.NewReader(body))
	if rsp != nil {
		defer rsp.Body.Close()
	}
	if err == nil {
		var ne newEncryptionResponse

		if rsp.StatusCode == http.StatusCreated {
			err = json.NewDecoder(rsp.Body).Decode(&ne)
		} else {
			err = errors.New("unexpected response: " + rsp.Status)
		}

		if err == nil {
			srsa, _ := c.srsa()
			err = enc.init(ne, srsa)
		}
	}
	if err != nil {
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
func (this *Encryption) Begin() ([]byte, error) {
	var hdr []byte
	var h header
	var err error

	if this.cipher != nil {
		return nil, errors.New("encryption already in progress")
	}
	if this.key.uses.cur >= this.key.uses.max {
		return nil, errors.New("maximum key uses exceeded")
	}

	h.version = 0
	h.v0.flags = 0
	if this.algo.aad {
		// if the algorithm supports additional authenticated
		// data, then authenticate the header
		h.v0.flags |= headerV0FlagAAD
	}
	h.v0.algo = uint8(this.algo.id)
	h.v0.iv = make([]byte, this.algo.len.iv)
	h.v0.key = this.key.enc

	_, err = rand.Read(h.v0.iv)
	if err == nil {
		var c cipher

		hdr = h.serialize()

		if this.algo.aad {
			c, err = this.algo.newCipher(
				this.key.raw, h.v0.iv, hdr)
		} else {
			c, err = this.algo.newCipher(
				this.key.raw, h.v0.iv)
		}
		if err == nil {
			this.cipher = &c
			this.key.uses.cur++
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
func (this *Encryption) Update(plaintext []byte) ([]byte, error) {
	return this.cipher.encipher(plaintext), nil
}

// End completes the encryption of a plain text message. For certain
// algorithms, message authenticity checks will be performed, and any
// remaining plain text will be returned.
//
// error is nil upon success and the byte slice may or may not contain
// any remaining plain text. If error is non-nil, any previously decrypted
// plain text should be discarded.
func (this *Encryption) End() ([]byte, error) {
	res, err := this.cipher.close()
	this.cipher = nil
	return res, err
}

// Close cleans up the Encryption object and resets it to its default values.
// An error returned by this function is a result of a miscommunication with
// the server, and the object is reset regardless.
func (this *Encryption) Close() error {
	var err error

	// the patch command is only necessary if the key was
	// used fewer times than requested
	if this.key.uses.cur < this.key.uses.max {
		var rsp *http.Response

		body, _ := json.Marshal(
			updateEncryptionRequest{
				Requested: this.key.uses.max,
				Actual:    this.key.uses.cur})

		endp := this.host
		endp += "/api/v0/encryption/key"
		endp += "/" + this.key.fingerprint
		endp += "/" + this.session

		rsp, err = this.client.Patch(
			endp, "application/json", bytes.NewBuffer(body))
		rsp.Body.Close()
	}

	*this = Encryption{}

	return err
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
