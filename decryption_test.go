package ubiq

import (
	"bytes"
	"testing"
)

func TestNoDecryption(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	decryption, err := NewDecryption(credentials)
	if decryption != nil {
		defer decryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSimpleDecryption(t *testing.T) {
	var pt []byte = []byte("abc")

	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := Encrypt(credentials, pt)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := Decrypt(credentials, ct)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, recovered) {
		t.FailNow()
	}
}

func TestSingleDecryption(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	encryption, err := NewEncryption(credentials, 1)
	if encryption != nil {
		defer encryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	ct, err := encryption.Begin()
	if err != nil {
		t.Fatal(err)
	}

	tmp, _ := encryption.Update([]byte("abc"))
	ct = append(ct, tmp...)

	tmp, err = encryption.End()
	if err != nil {
		t.Fatal(err)
	}

	ct = append(ct, tmp...)

	decryption, err := NewDecryption(credentials)
	if decryption != nil {
		defer decryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	pt, err := decryption.Begin()
	if err != nil {
		t.Fatal(err)
	}

	tmp, err = decryption.Update(ct)
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	tmp, err = decryption.End()
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	if !bytes.Equal(pt, []byte("abc")) {
		t.FailNow()
	}
}
