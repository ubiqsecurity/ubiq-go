package ubiq

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestGetFFS(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	enc, err := NewFPEncryption(credentials, "ALPHANUM_SSN")
	if err != nil {
		t.Fatal(err)
	}
	enc.Close()
}

func testFPE(t *testing.T, ffs, pt string) {
	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := FPEncrypt(c, ffs, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	rt, err := FPDecrypt(c, ffs, ct, nil)
	if err != nil {
		t.Fatal(err)
	}

	if pt != rt {
		t.Fatalf("bad recovered plaintext: \"%s\" vs. \"%s\"", pt, rt)
	}
}

func TestFPEAlnumSSN(t *testing.T) {
	testFPE(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestFPEBirthdate(t *testing.T) {
	testFPE(t, "BIRTH_DATE", "04-20-1969")
}
func TestFPESSN(t *testing.T) {
	testFPE(t, "SSN", "987-65-4321")
}
func TestFPEUTF8(t *testing.T) {
	testFPE(t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}

func testFPEForSearch(t *testing.T, ffs, pt string) {
	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := FPEncryptForSearch(c, ffs, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := range ct {
		rt, err := FPDecrypt(c, ffs, ct[i], nil)
		if err != nil {
			t.Fatal(err)
		}

		if pt != rt {
			t.Fatalf(
				"bad recovered plaintext: \"%s\" vs. \"%s\"",
				pt, rt)
		}
	}
}

func TestFPEAlnumSSNForSearch(t *testing.T) {
	testFPEForSearch(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestFPEBirthdateForSearch(t *testing.T) {
	testFPEForSearch(t, "BIRTH_DATE", "04-20-1969")
}
func TestFPESSNForSearch(t *testing.T) {
	testFPEForSearch(t, "SSN", "987-65-4321")
}
func TestFPEUTF8ForSearch(t *testing.T) {
	testFPEForSearch(
		t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}

type FPETestRecord struct {
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	Dataset    string `json:"dataset"`
}

type FPEOperations struct {
	enc *FPEncryption
	dec *FPDecryption
}

type FPEPerformanceCounter struct {
	Count    int
	Duration struct {
		Encrypt time.Duration
		Decrypt time.Duration
	}
}

func TestFPE1M(t *testing.T) {
	file, err := os.Open("1m.json")
	if err != nil {
		t.Skip(err)
	}
	defer file.Close()

	raw, err := ioutil.ReadAll(file)
	if err != nil {
		t.Skip(err)
	}

	var records []FPETestRecord
	err = json.Unmarshal([]byte(raw), &records)
	if err != nil {
		t.Skip(err)
	}

	creds, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	var ops map[string]FPEOperations = make(map[string]FPEOperations)
	for i, _ := range records {
		rec := &records[i]

		op, ok := ops[rec.Dataset]
		if !ok {
			op.enc, err = NewFPEncryption(creds, rec.Dataset)
			if err != nil {
				t.Fatal(err)
			}
			defer op.enc.Close()

			op.dec, err = NewFPDecryption(creds, rec.Dataset)
			if err != nil {
				t.Fatal(err)
			}
			defer op.dec.Close()

			ops[rec.Dataset] = op
		}

		ct, err := op.enc.Cipher(rec.Plaintext, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ct != rec.Ciphertext {
			t.Fatalf("encryption(%v): %v != %v",
				i, ct, rec.Ciphertext)
		}

		pt, err := op.dec.Cipher(rec.Ciphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		if pt != rec.Plaintext {
			t.Fatalf("decryption(%v): %v != %v",
				i, pt, rec.Plaintext)
		}
	}
}
