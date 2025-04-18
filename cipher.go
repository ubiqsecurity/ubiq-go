package ubiq

import (
	"crypto/aes"
	goCipher "crypto/cipher"
	"errors"
	"fmt"
	"strings"
)

// cipher holds pointers to different types of encryption schemes.
// only one of the pointers is valid at any given time; and the
// encipher(), decipher(), and close() functions behave differently
// to handle the differences in operation between them, abstracting
// away the different cipher modes.
type cipher struct {
	aead   *aeadIf
	block  *goCipher.BlockMode
	stream *goCipher.Stream
}

func (c cipher) encipher(plaintext []byte) []byte {
	var res []byte
	if c.aead != nil {
		res = (*c.aead).EncryptUpdate(plaintext)
	}
	return res
}

func (c cipher) decipher(ciphertext []byte) []byte {
	var res []byte
	if c.aead != nil {
		res = (*c.aead).DecryptUpdate(ciphertext)
	}
	return res
}

// close must be called when an encryption has completed
// when no arguments are given, close() assumes that an
// encryption is being ended. when a single argument is
// provided, decryption is assumed. the argument for decryption
// is the tag associated with authenticated algorithms. if
// the algorithm does not support authentication, then the
// argument must be present but will be ignored. callers should
// pass nil in this situation.
func (c *cipher) close(args ...[]byte) ([]byte, error) {
	var res []byte
	var err error

	if c.aead != nil {
		if len(args) == 0 {
			var tag []byte
			res, tag = (*c.aead).EncryptEnd()
			res = append(res, tag...)
		} else {
			var ok bool
			res, ok = (*c.aead).DecryptEnd(args[0])
			if !ok {
				err = errors.New("authentication failed")
			}
		}

		c.aead = nil
	}

	return res, err
}

func verifyKeyAndIvLength(key, iv []byte, keylen, ivlen int) error {
	str := "invalid %s size: have %d, want %d"
	if len(key) != keylen {
		return fmt.Errorf(str, "key", len(key), keylen)
	}
	if len(iv) != ivlen {
		return fmt.Errorf(str, "iv", len(iv), ivlen)
	}
	return nil
}

// signature most conform to algorithm::newCipher
func newAesGcm(key, iv []byte, keylen int, args ...[]byte) (cipher, error) {
	var c cipher
	var block goCipher.Block

	err := verifyKeyAndIvLength(key, iv, keylen, gcmStandardNonceSize)
	if err == nil {
		block, err = aes.NewCipher(key)
		if err == nil {
			var aead aeadIf

			aead, err = newGCM(block)
			if err == nil {
				var aad []byte = nil

				c.aead = &aead

				if len(args) > 0 {
					aad = args[0]
				}

				(*c.aead).Begin(iv, aad)
			}
		}
	}
	return c, err
}

type algorithmLengths struct {
	key, iv, tag int
}
type algorithm struct {
	id   int
	name string
	// caller passes key, iv, and aad (if any)
	// the final argument may be omitted
	newCipher func([]byte, []byte, ...[]byte) (cipher, error)
	aad       bool
	len       algorithmLengths
}

func supportedAlgorithms() *[]algorithm {
	return &[]algorithm{
		{id: 0, name: "aes-256-gcm",
			newCipher: func(key, iv []byte, args ...[]byte) (
				cipher, error) {
				return newAesGcm(key, iv, 32, args...)
			},
			aad: true,
			len: algorithmLengths{
				key: 32,
				iv:  gcmStandardNonceSize,
				tag: gcmTagSize}},
		{id: 1, name: "aes-128-gcm",
			newCipher: func(key, iv []byte, args ...[]byte) (
				cipher, error) {
				return newAesGcm(key, iv, 16, args...)
			},
			aad: true,
			len: algorithmLengths{
				key: 16,
				iv:  gcmStandardNonceSize,
				tag: gcmTagSize}},
	}
}

func getAlgorithmByName(name string) (algorithm, error) {
	lowername := strings.ToLower(name)

	for _, a := range *supportedAlgorithms() {
		if a.name == lowername {
			return a, nil
		}
	}

	return algorithm{}, errors.New("algorithm not found")
}

func getAlgorithmById(id int) (algorithm, error) {
	for _, a := range *supportedAlgorithms() {
		if a.id == id {
			return a, nil
		}
	}

	return algorithm{}, errors.New("algorithm not found")
}
