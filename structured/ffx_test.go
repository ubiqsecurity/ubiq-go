package structured

import (
	"math/big"
	"testing"
)

func TestNewFFXKeyLength(t *testing.T) {
	var err error
	var key []byte

	var bad_lengths []int = []int{15, 23, 26, 30, 33, 64}
	var good_lengths []int = []int{16, 24, 32}

	twk := make([]byte, 4)

	for _, len := range bad_lengths {
		key = make([]byte, len)
		_, err = newFFX(key, twk, 1024, 0, 0, 10)
		if err == nil {
			t.FailNow()
		}
	}

	for _, len := range good_lengths {
		key = make([]byte, len)
		_, err = newFFX(key, twk, 1024, 0, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Invalid input strings that would cause index out of range with small alphabets (<=62 chars)
func TestBigIntToRunesInvalidInputSmallAlphabet(t *testing.T) {
	// Create a small alphabet (<=62 characters)
	alpha, err := NewAlphabet("0123456789abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		t.Fatal(err)
	}

	// Test case 1: BigInt that would require more digits than allocated space
	// Create a number that needs more than 5 digits in base-36
	bigNum := big.NewInt(0)
	bigNum.SetString("zzzzzz", 36) // 6 z's in base-36 = huge number

	// Try to fit it in only 5 characters - should return error instead of panic
	_, err = BigIntToRunes(&alpha, bigNum, 5)
	if err == nil {
		t.Fatal("Expected error for invalid input string (too large for output length), got nil")
	}
	if err.Error() != "invalid input string" {
		t.Fatalf("Expected 'invalid input string' error, got: %v", err)
	}
}

// Invalid input strings that would cause index out of range with large alphabets (>62 chars)
func TestBigIntToRunesInvalidInputLargeAlphabet(t *testing.T) {
	// Create a large alphabet (>62 characters) to trigger the large alphabet code path
	largeAlphabetStr := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n"
	alpha, err := NewAlphabet(largeAlphabetStr)
	if err != nil {
		t.Fatal(err)
	}

	// Verify we're testing a large alphabet (>62)
	if alpha.Len() <= defaultAlphabet.Len() {
		t.Fatalf("Expected alphabet length > 62, got %d", alpha.Len())
	}

	// Test: BigInt that would require more digits than allocated space
	// For a given radix, the smallest number requiring N digits is radix^(N-1)
	// For example: in base-10, smallest 3-digit number is 10^2 = 100
	// Here: we create the smallest 15-digit number (radix^14) and try to fit it
	// in only 11 characters - this reproduces the production panic scenario
	radix := int64(alpha.Len())
	bigNum := big.NewInt(0)
	bigNum.Exp(big.NewInt(radix), big.NewInt(14), nil) // radix^14 = smallest 15-digit number

	// Try to fit a 15-digit number in 11 characters - should return error instead of panic
	_, err = BigIntToRunes(&alpha, bigNum, 11)
	if err == nil {
		t.Fatal("Expected error for invalid input string (too large for output length), got nil")
	}
	if err.Error() != "invalid input string" {
		t.Fatalf("Expected 'invalid input string' error, got: %v", err)
	}
}

// TestBigIntToRunesValidInputLargeAlphabet tests that valid inputs still work correctly
func TestBigIntToRunesValidInputLargeAlphabet(t *testing.T) {
	largeAlphabetStr := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n"
	alpha, err := NewAlphabet(largeAlphabetStr)
	if err != nil {
		t.Fatal(err)
	}

	// Test valid conversion: small number in large alphabet with sufficient space
	bigNum := big.NewInt(12345)
	result, err := BigIntToRunes(&alpha, bigNum, 20)
	if err != nil {
		t.Fatalf("Expected no error for valid input, got: %v", err)
	}
	if len(result) != 20 {
		t.Fatalf("Expected result length 20, got %d", len(result))
	}
}
