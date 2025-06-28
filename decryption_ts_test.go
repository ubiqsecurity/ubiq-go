package ubiq

import (
	"bytes"
	"sync"
	"testing"
)

func TestNoDecryptionTS(t *testing.T) {
	var err error
	initializeCreds()

	decryption, err := NewDecryptionTS(credentials)
	if decryption != nil {
		defer decryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSingleDecryptionTS(t *testing.T) {
	var err error
	initializeCreds()

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

	decryption, err := NewDecryptionTS(credentials)
	if decryption != nil {
		defer decryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	pt, session := decryption.Begin()
	if err != nil {
		t.Fatal(err)
	}

	tmp, err = decryption.Update(session, ct)
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	tmp, err = decryption.End(session)
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	if !bytes.Equal(pt, []byte("abc")) {
		t.FailNow()
	}
}

func doDecrypt(dec *DecryptionTS, enc_data []byte, expected_data []byte, t *testing.T) {
	pt, session := dec.Begin()

	tmp, err := dec.Update(session, enc_data)
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	tmp, err = dec.End(session)
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	if !bytes.Equal(pt, expected_data) {
		t.FailNow()
	}
}

func TestThreadedDecryption(t *testing.T) {

	initializeCreds()
	var pt []byte = []byte("abc")
	var wg sync.WaitGroup
	parallel := 50
	enc_data, _ := Encrypt(credentials, pt)

	decryption, _ := NewDecryptionTS(credentials)

	// Run once so key is cached.
	doDecrypt(decryption, enc_data, pt, t)

	wg.Add(parallel)

	for i := 0; i < parallel; i++ {
		go func(i int) {
			defer wg.Done()

			doDecrypt(decryption, enc_data, pt, t)

		}(i)
	}
	wg.Wait()

}
