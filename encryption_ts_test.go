package ubiq

import (
	"sync"
	"testing"
)

func TestNoEncryptionTS(t *testing.T) {
	initializeCreds()

	encryption, err := NewEncryptionTS(credentials, 1)
	if encryption != nil {
		defer encryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSingleEncryptionTS(t *testing.T) {
	var err error
	initializeCreds()

	encryption, err := NewEncryptionTS(credentials, 1)
	if encryption != nil {
		defer encryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	ct, session, err := encryption.Begin()
	if err != nil {
		t.Fatal(err)
	}

	tmp, _ := encryption.Update(session, []byte("abc"))
	ct = append(ct, tmp...)

	tmp, err = encryption.End(session)
	if err != nil {
		t.Fatal(err)
	}

	ct = append(ct, tmp...)
}

func TestThreadedEncryption(t *testing.T) {
	initializeCreds()
	var wg sync.WaitGroup
	parallel := 50

	encryption, _ := NewEncryptionTS(credentials, 50)

	wg.Add(parallel)

	for i := 0; i < parallel; i++ {
		go func(i int) {
			defer wg.Done()

			ct, session, err := encryption.Begin()
			if err != nil {
				t.Fatal(err)
			}

			tmp, _ := encryption.Update(session, []byte("abc"))
			ct = append(ct, tmp...)

			tmp, err = encryption.End(session)
			if err != nil {
				t.Fatal(err)
			}

			ct = append(ct, tmp...)

		}(i)
	}
	wg.Wait()
}
