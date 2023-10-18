package ubiq

import (
	"testing"
)

func TestNoEncryption(t *testing.T) {
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
}

func TestSimpleEncryption(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Encrypt(credentials, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSingleEncryption(t *testing.T) {
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
}

func TestTooManyEncryption(t *testing.T) {
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

	_, err = encryption.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = encryption.End()
	if err != nil {
		t.Fatal(err)
	}

	// no longer enforcing maximum number of uses
	_, err = encryption.Begin()
	if err != nil {
		t.Fatal(err)
	}
}
