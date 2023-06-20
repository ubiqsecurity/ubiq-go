package ubiq

import (
	"testing"
)

func TestGetFFS(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewFPEncryption(credentials, "ALPHANUM_SSN")
	if err != nil {
		t.Fatal(err)
	}
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
