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

func TestGetDataset(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	enc, err := NewStructuredEncryption(credentials, "ALPHANUM_SSN")
	if err != nil {
		t.Fatal(err)
	}
	enc.Close()
}

func testStructured(t *testing.T, dataset, pt string) {
	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := StructuredEncrypt(c, dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	rt, err := StructuredDecrypt(c, dataset, ct, nil)
	if err != nil {
		t.Fatal(err)
	}

	if pt != rt {
		t.Fatalf("bad recovered plaintext: \"%s\" vs. \"%s\"", pt, rt)
	}
}

func TestStructuredAlnumSSN(t *testing.T) {
	testStructured(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestStructuredBirthdate(t *testing.T) {
	testStructured(t, "BIRTH_DATE", "04-20-1969")
}
func TestStructuredSSN(t *testing.T) {
	testStructured(t, "SSN", "987-65-4321")
}
func TestStructuredUTF8(t *testing.T) {
	testStructured(t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}
func TestStructuredUTF8Complex(t *testing.T) {
	testStructured(t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testStructuredForSearchLocal(t *testing.T, dataset, pt string) {
	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := StructuredEncryptForSearch(c, dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := range ct {
		rt, err := StructuredDecrypt(c, dataset, ct[i], nil)
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

func TestStructuredAlnumSSNForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestStructuredBirthdateForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(t, "BIRTH_DATE", "04-20-1969")
}
func TestStructuredSSNForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(t, "SSN", "987-65-4321")
}
func TestStructuredUTF8ForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(
		t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}
func TestStructuredUTF8ComplexForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testStructuredForSearchRemote(t *testing.T, dataset, pt, expected_ct string) {
	if val, ok := os.LookupEnv("CI"); !ok || val != "true" {
		t.Skip()
	}

	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := StructuredEncryptForSearch(c, dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	var found bool = false
	for i := range ct {
		rt, err := StructuredDecrypt(c, dataset, ct[i], nil)
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
			dataset)
	}
}

func TestStructuredAlnumSSNForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"ALPHANUM_SSN",
		";0123456-789ABCDEF|",
		";!!!E7`+-ai1ykOp8r|")
}
func TestStructuredBirthdateForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"BIRTH_DATE",
		";01\\02-1960|",
		";!!\\!!-oKzi|")
}
func TestStructuredSSNForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"SSN",
		"-0-1-2-3-4-5-6-7-8-9-",
		"-0-0-0-0-1-I-L-8-j-D-")
}
func TestStructuredUTF8ComplexForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ",
		"ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ")
}

type StructuredTestRecord struct {
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	Dataset    string `json:"dataset"`
}

type StructuredPerformanceCounter struct {
	Count    int
	Duration struct {
		Encrypt time.Duration
		Decrypt time.Duration
	}
}

type StructuredOperations struct {
	enc *StructuredEncryption
	dec *StructuredDecryption

	perf StructuredPerformanceCounter
}

func TestStructured1M(t *testing.T) {
	file, err := os.Open("1m.json")
	if err != nil {
		t.Skip(err)
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		t.Skip(err)
	}

	var records []StructuredTestRecord
	err = json.Unmarshal([]byte(raw), &records)
	if err != nil {
		t.Skip(err)
	}

	creds, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	var ops map[string]*StructuredOperations = make(map[string]*StructuredOperations)
	for i, _ := range records {
		rec := &records[i]

		op, ok := ops[rec.Dataset]
		if !ok {
			var _op StructuredOperations

			_op.enc, err = NewStructuredEncryption(creds, rec.Dataset)
			if err != nil {
				t.Fatal(err)
			}
			defer _op.enc.Close()

			_op.dec, err = NewStructuredDecryption(creds, rec.Dataset)
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
