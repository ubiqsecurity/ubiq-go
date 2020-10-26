package ubiq

import (
	"bytes"
	"crypto/aes"
	goCipher "crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func TestGcm(t *testing.T) {
	key, _ := hex.DecodeString(
		"6368616e676520746869732070617373776f726420746f206120736563726574")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	gogcm, err := goCipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	ubiqgcm, err := newGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	goct := gogcm.Seal(nil, nonce, []byte("exampleplaintext"), nil)

	ubiqgcm.Begin(nonce, nil)
	ubiqct := ubiqgcm.EncryptUpdate([]byte("example"))
	ubiqct = append(ubiqct, ubiqgcm.EncryptUpdate([]byte("plain"))...)
	ubiqct = append(ubiqct, ubiqgcm.EncryptUpdate([]byte("text"))...)
	tail, tag := ubiqgcm.EncryptEnd()
	tail = append(tail, tag...)
	if !bytes.Equal(goct, append(ubiqct, tail...)) {
		t.FailNow()
	}

	gopt, err := gogcm.Open(nil, nonce, goct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gopt, []byte("exampleplaintext")) {
		t.FailNow()
	}

	ubiqgcm.Begin(nonce, nil)
	ubiqpt := ubiqgcm.DecryptUpdate(ubiqct[:len(ubiqct)/2])
	ubiqpt = append(
		ubiqpt, ubiqgcm.DecryptUpdate(ubiqct[len(ubiqct)/2:])...)
	tail, ok := ubiqgcm.DecryptEnd(tag)
	ubiqpt = append(ubiqpt, tail...)
	if !ok {
		t.FailNow()
	}
	if !bytes.Equal(gopt, ubiqpt) {
		t.FailNow()
	}
}
