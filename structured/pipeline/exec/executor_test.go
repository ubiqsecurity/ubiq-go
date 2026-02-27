package exec

import (
	"encoding/base64"
	"testing"

	// NOTE: Cannot import main ubiq package here due to import cycle:
	// - ubiq imports structured/pipeline/exec
	// - exec test would import ubiq
	// The integration tests are covered by the main package tests in ../../structured_test.go
	// "gitlab.com/ubiqsecurity/ubiq-go/v2"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// NOTE: Integration tests cannot be in this package due to import cycle.
// The integration tests are fully covered by the tests in ../../structured_test.go which:
// - Use real API credentials
// - Fetch real dataset definitions
// - Test encryption/decryption roundtrips
// - Test CipherForSearch with multiple key versions

// TestEncryptDecrypt_BasicRoundtrip tests basic encryption/decryption without JSON vectors.
// This is a simpler unit test that doesn't require API calls.
func TestEncryptDecrypt_BasicRoundtrip(t *testing.T) {
	// Create a mock dataset info
	inputAlphabet, _ := structured.NewAlphabet("0123456789")
	outputAlphabet, _ := structured.NewAlphabet("0123456789")
	passthroughAlphabet, _ := structured.NewAlphabet("-")

	dataset := &pipeline.DatasetInfo{
		Name:                  "TEST_SSN",
		Algorithm:             "FF1",
		InputCharacterSet:     "0123456789",
		OutputCharacterSet:    "0123456789",
		PassthroughCharacters: "-",
		InputLengthMin:        9,
		InputLengthMax:        11,
		NumEncodingBits:       2,
		Tweak:                 base64.StdEncoding.EncodeToString([]byte("test")),
		TweakLengthMin:        0,
		TweakLengthMax:        16,
		InputAlphabet:         &inputAlphabet,
		OutputAlphabet:        &outputAlphabet,
		PassthroughAlphabet:   &passthroughAlphabet,
		PassthroughRules: []pipeline.PassthroughRule{
			{Type: "passthrough", Value: "-", Priority: 1},
		},
	}

	// Create a mock FF1 algorithm (identity transform for testing)
	mockAlgo := &mockFF1Algorithm{}

	plaintext := "123-45-6789"
	keyNumber := 0

	// Test encryption
	ciphertext, err := Encrypt(dataset, plaintext, nil, keyNumber, mockAlgo)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	t.Logf("Plaintext:  %s", plaintext)
	t.Logf("Ciphertext: %s", ciphertext)

	// Test decryption
	algoFactory := func(kn int) (FF1Algorithm, error) {
		return mockAlgo, nil
	}

	decrypted, decodedKeyNum, err := Decrypt(dataset, ciphertext, nil, algoFactory)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify roundtrip
	if decrypted != plaintext {
		t.Errorf("roundtrip failed:\n  original:  %s\n  decrypted: %s", plaintext, decrypted)
	}

	if decodedKeyNum != keyNumber {
		t.Errorf("key number mismatch: got %d, expected %d", decodedKeyNum, keyNumber)
	}
}

// mockFF1Algorithm is a simple mock that performs identity transform for testing
type mockFF1Algorithm struct{}

func (m *mockFF1Algorithm) EncryptRunes(input []rune, tweak []byte) ([]rune, error) {
	// Identity transform - just return input
	return input, nil
}

func (m *mockFF1Algorithm) DecryptRunes(input []rune, tweak []byte) ([]rune, error) {
	// Identity transform - just return input
	return input, nil
}
