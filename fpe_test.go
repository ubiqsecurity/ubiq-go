package ubiq

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
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
func TestFPEUTF8Complex(t *testing.T) {
	testFPE(t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testFPEForSearchLocal(t *testing.T, ffs, pt string) {
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

func TestFPEAlnumSSNForSearchLocal(t *testing.T) {
	testFPEForSearchLocal(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestFPEBirthdateForSearchLocal(t *testing.T) {
	testFPEForSearchLocal(t, "BIRTH_DATE", "04-20-1969")
}
func TestFPESSNForSearchLocal(t *testing.T) {
	testFPEForSearchLocal(t, "SSN", "987-65-4321")
}
func TestFPEUTF8ForSearchLocal(t *testing.T) {
	testFPEForSearchLocal(
		t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}
func TestFPEUTF8ComplexForSearchLocal(t *testing.T) {
	testFPEForSearchLocal(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testFPEForSearchRemote(t *testing.T, ffs, pt, expected_ct string) {
	if val, ok := os.LookupEnv("CI"); !ok || val != "true" {
		t.Skip()
	}

	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := FPEncryptForSearch(c, ffs, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	var found bool = false
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

		found = found || (expected_ct == ct[i])
	}

	if !found {
		t.Fatalf("%s: failed to find expected cipher text in search",
			ffs)
	}
}

func TestFPEAlnumSSNForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"ALPHANUM_SSN",
		";0123456-789ABCDEF|",
		";!!!E7`+-ai1ykOp8r|")
}
func TestFPEBirthdateForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"BIRTH_DATE",
		";01\\02-1960|",
		";!!\\!!-oKzi|")
}
func TestFPESSNForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"SSN",
		"-0-1-2-3-4-5-6-7-8-9-",
		"-0-0-0-0-1-I-L-8-j-D-")
}
func TestFPEUTF8ComplexForSearchRemote(t *testing.T) {
	testFPEForSearchRemote(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ",
		"ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ")
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

	var ops map[string]*FPEOperations = make(map[string]*FPEOperations)
	for i, _ := range records {
		rec := &records[i]

		op, ok := ops[rec.Dataset]
		if !ok {
			var _op FPEOperations

			_op.enc, err = NewFPEncryption(creds, rec.Dataset)
			if err != nil {
				t.Fatal(err)
			}
			defer _op.enc.Close()

			_op.dec, err = NewFPDecryption(creds, rec.Dataset)
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
