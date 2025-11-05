package ubiq

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestDeprecatedGetFFS(t *testing.T) {
	initializeCreds()

	enc, err := NewFPEncryption(credentials, "ALPHANUM_SSN")
	if err != nil {
		t.Fatal(err)
	}
	enc.Close()
}

func testDeprecatedFPE(t *testing.T, ffs, pt string) {
	initializeCreds()

	ct, err := FPEncrypt(credentials, ffs, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	rt, err := FPDecrypt(credentials, ffs, ct, nil)
	if err != nil {
		t.Fatal(err)
	}

	if pt != rt {
		t.Fatalf("bad recovered plaintext: \"%s\" vs. \"%s\"", pt, rt)
	}
}

func TestDeprecatedFPEAlnumSSN(t *testing.T) {
	testDeprecatedFPE(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestDeprecatedFPEBirthdate(t *testing.T) {
	testDeprecatedFPE(t, "BIRTH_DATE", "04-20-1969")
}
func TestDeprecatedFPESSN(t *testing.T) {
	testDeprecatedFPE(t, "SSN", "987-65-4321")
}
func TestDeprecatedFPEUTF8(t *testing.T) {
	testDeprecatedFPE(t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}
func TestDeprecatedFPEUTF8Complex(t *testing.T) {
	testDeprecatedFPE(t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testDeprecatedFPEForSearchLocal(t *testing.T, ffs, pt string) {
	initializeCreds()

	ct, err := FPEncryptForSearch(credentials, ffs, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := range ct {
		rt, err := FPDecrypt(credentials, ffs, ct[i], nil)
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

func TestDeprecatedFPEAlnumSSNForSearchLocal(t *testing.T) {
	testDeprecatedFPEForSearchLocal(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestDeprecatedFPEBirthdateForSearchLocal(t *testing.T) {
	testDeprecatedFPEForSearchLocal(t, "BIRTH_DATE", "04-20-1969")
}
func TestDeprecatedFPESSNForSearchLocal(t *testing.T) {
	testDeprecatedFPEForSearchLocal(t, "SSN", "987-65-4321")
}
func TestDeprecatedFPEUTF8ForSearchLocal(t *testing.T) {
	testDeprecatedFPEForSearchLocal(
		t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}
func TestDeprecatedFPEUTF8ComplexForSearchLocal(t *testing.T) {
	testDeprecatedFPEForSearchLocal(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testFPEForSearchRemote(t *testing.T, ffs, pt string) {
	initializeCreds()

	encryptedText, err := FPEncrypt(credentials, ffs, pt, nil)

	ct, err := FPEncryptForSearch(credentials, ffs, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	var found bool = false
	for i := range ct {
		rt, err := FPDecrypt(credentials, ffs, ct[i], nil)
		if err != nil {
			t.Fatal(err)
		}

		if pt != rt {
			t.Fatalf(
				"bad recovered plaintext: \"%s\" vs. \"%s\"",
				pt, rt)
		}

		found = found || (encryptedText == ct[i])
	}

	if !found {
		t.Fatalf("%s: failed to find expected cipher text in search",
			ffs)
	}
}

func TestDeprecatedFPEAlnumSSNForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"ALPHANUM_SSN",
		";0123456-789ABCDEF|")
}
func TestDeprecatedFPEBirthdateForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"BIRTH_DATE",
		";01\\02-1960|")
}
func TestDeprecatedFPESSNForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"SSN",
		"-0-1-2-3-4-5-6-7-8-9-")
}
func TestDeprecatedFPEUTF8ComplexForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

type FPETestRecord struct {
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	Dataset    string `json:"dataset"`
}

type FPEPerformanceCounter struct {
	Count    int
	Duration struct {
		Encrypt time.Duration
		Decrypt time.Duration
	}
}

type FPEOperations struct {
	enc *FPEncryption
	dec *FPDecryption

	perf FPEPerformanceCounter
}

func TestDeprecatedFPE1M(t *testing.T) {
	file, err := os.Open("1m.json")
	if err != nil {
		t.Skip(err)
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		t.Skip(err)
	}

	var records []FPETestRecord
	err = json.Unmarshal([]byte(raw), &records)
	if err != nil {
		t.Skip(err)
	}

	initializeCreds()

	var ops map[string]*FPEOperations = make(map[string]*FPEOperations)
	for i := range records {
		rec := &records[i]

		op, ok := ops[rec.Dataset]
		if !ok {
			var _op FPEOperations

			_op.enc, err = NewFPEncryption(credentials, rec.Dataset)
			if err != nil {
				t.Fatal(err)
			}
			defer _op.enc.Close()

			_op.dec, err = NewFPDecryption(credentials, rec.Dataset)
			if err != nil {
				t.Fatal(err)
			}
			defer _op.dec.Close()

			ops[rec.Dataset] = &_op
			op = &_op
		}

		beg := time.Now()
		ct, err := op.enc.Cipher(rec.Plaintext, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ct != rec.Ciphertext {
			t.Fatalf("encryption(%v): %v != %v",
				i, ct, rec.Ciphertext)
		}
		op.perf.Duration.Encrypt += time.Since(beg)

		beg = time.Now()
		pt, err := op.dec.Cipher(rec.Ciphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		if pt != rec.Plaintext {
			t.Fatalf("decryption(%v): %v != %v",
				i, pt, rec.Plaintext)
		}
		op.perf.Duration.Decrypt += time.Since(beg)

		op.perf.Count++
	}

	for dset, op := range ops {
		fmt.Println(dset + ": " + strconv.Itoa(op.perf.Count))
		fmt.Printf("\tencrypt: %v / per\n",
			time.Duration(int64(op.perf.Duration.Encrypt)/
				int64(op.perf.Count)))
		fmt.Printf("\tdecrypt: %v / per\n",
			time.Duration(int64(op.perf.Duration.Decrypt)/
				int64(op.perf.Count)))
	}
}
