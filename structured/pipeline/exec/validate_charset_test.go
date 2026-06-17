package exec

import (
	"encoding/base64"
	"strings"
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// genericStringDataset builds a dataset resembling a "Generic String (not-encoded)"
// definition: a custom alphabet that is not a prefix of the default alphabet and
// no input encoding. This is the configuration that previously panicked when the
// plaintext contained an out-of-charset character.
func genericStringDataset(t *testing.T) *pipeline.DatasetInfo {
	t.Helper()
	const charset = "abcdefghij" // radix 10, NOT a default-alphabet prefix
	alpha, err := structured.NewAlphabet(charset)
	if err != nil {
		t.Fatal(err)
	}
	return &pipeline.DatasetInfo{
		Name:               "GENERIC_STRING",
		Algorithm:          "FF1",
		InputCharacterSet:  charset,
		OutputCharacterSet: charset,
		InputLengthMin:     1,
		InputLengthMax:     32,
		NumEncodingBits:    0,
		Tweak:              base64.StdEncoding.EncodeToString([]byte("test")),
		TweakLengthMin:     0,
		TweakLengthMax:     16,
		InputEncoding:      "", // not-encoded
		InputAlphabet:      &alpha,
		OutputAlphabet:     &alpha,
	}
}

// TestEncrypt_OutOfCharsetReturnsError ensures an out-of-charset character yields
// an error instead of panicking ("index out of range [-1]").
func TestEncrypt_OutOfCharsetReturnsError(t *testing.T) {
	dataset := genericStringDataset(t)

	_, err := Encrypt(dataset, "abc!efghij", nil, 0, &mockFF1Algorithm{})
	if err == nil {
		t.Fatal("expected an error for out-of-charset input, got nil")
	}
	if !strings.Contains(err.Error(), "invalid input string character(s)") {
		t.Fatalf("expected charset validation error, got: %v", err)
	}
}

// TestEncrypt_InCharsetStillSucceeds ensures valid input is unaffected by the new
// validation step.
func TestEncrypt_InCharsetStillSucceeds(t *testing.T) {
	dataset := genericStringDataset(t)

	if _, err := Encrypt(dataset, "abcdefghij", nil, 0, &mockFF1Algorithm{}); err != nil {
		t.Fatalf("valid in-charset input should encrypt without error, got: %v", err)
	}
}

// TestDecrypt_OutOfCharsetReturnsError ensures the decrypt path is guarded too.
func TestDecrypt_OutOfCharsetReturnsError(t *testing.T) {
	dataset := genericStringDataset(t)

	algoFactory := func(int) (FF1Algorithm, error) { return &mockFF1Algorithm{}, nil }
	_, _, err := Decrypt(dataset, "abc!efghij", nil, algoFactory)
	if err == nil {
		t.Fatal("expected an error for out-of-charset ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "invalid input string character(s)") {
		t.Fatalf("expected charset validation error, got: %v", err)
	}
}
