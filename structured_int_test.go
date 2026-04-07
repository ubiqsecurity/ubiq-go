package ubiq

import (
	"testing"
)

func TestFormatIntegerForEncryption(t *testing.T) {
	tests := []struct {
		name      string
		value     int64
		minLength int
		expected  string
	}{
		{"positive_pad", 123, 6, "000123"},
		{"positive_nopad", 123456, 6, "123456"},
		{"positive_longer", 1234567, 6, "1234567"},
		{"negative_pad", -123, 6, "-000123"},
		{"negative_nopad", -123456, 6, "-123456"},
		{"zero", 0, 6, "000000"},
		{"single_digit", 5, 3, "005"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatIntegerForEncryption(tt.value, tt.minLength)
			if result != tt.expected {
				t.Errorf("formatIntegerForEncryption(%d, %d) = %q, want %q",
					tt.value, tt.minLength, result, tt.expected)
			}
		})
	}
}

func TestFormatIntegerInAlphabet(t *testing.T) {
	tests := []struct {
		name     string
		value    int64
		alphabet string
		expected string
	}{
		{"base10_simple", 123, "0123456789", "123"},
		{"base10_zero", 0, "0123456789", "0"},
		{"base16_simple", 255, "0123456789ABCDEF", "FF"},
		{"base16_larger", 256, "0123456789ABCDEF", "100"},
		{"base12_simple", 11, "0123456789AB", "B"},
		{"base12_larger", 144, "0123456789AB", "100"},
		{"base14_simple", 13, "0123456789ABCD", "D"},
		{"base32_simple", 60108, "0123456789ABCDEFGHIJKLMNOPQRSTUV", "1QMC"},
		{"custom_alphabet", 5, "abcdefghij", "f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatIntegerInAlphabet(tt.value, tt.alphabet)
			if result != tt.expected {
				t.Errorf("formatIntegerInAlphabet(%d, %q) = %q, want %q",
					tt.value, tt.alphabet, result, tt.expected)
			}
		})
	}
}

func TestParseIntegerInAlphabet(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		alphabet string
		expected int64
		wantErr  bool
	}{
		{"base10_simple", "123", "0123456789", 123, false},
		{"base10_zero", "0", "0123456789", 0, false},
		{"base16_simple", "FF", "0123456789ABCDEF", 255, false},
		{"base16_larger", "100", "0123456789ABCDEF", 256, false},
		{"base12_simple", "B", "0123456789AB", 11, false},
		// Regression: base-32 dataset alphabet (e.g. date type) where the
		// integer value (60108 days from epoch) needs 5 chars in base 10
		// but fits in 4 chars in base 32 ("1QMC").
		{"base32_simple", "1QMC", "0123456789ABCDEFGHIJKLMNOPQRSTUV", 60108, false},
		{"negative", "-123", "0123456789", -123, false},
		{"invalid_char", "XYZ", "0123456789", 0, true},
		{"custom_alphabet", "f", "abcdefghij", 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseIntegerInAlphabet(tt.value, tt.alphabet)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseIntegerInAlphabet(%q, %q) expected error, got nil",
						tt.value, tt.alphabet)
				}
				return
			}
			if err != nil {
				t.Errorf("parseIntegerInAlphabet(%q, %q) unexpected error: %v",
					tt.value, tt.alphabet, err)
				return
			}
			if result != tt.expected {
				t.Errorf("parseIntegerInAlphabet(%q, %q) = %d, want %d",
					tt.value, tt.alphabet, result, tt.expected)
			}
		})
	}
}

func TestPadLeft(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		minLength int
		padChar   byte
		expected  string
	}{
		{"needs_padding", "123", 6, '0', "000123"},
		{"exact_length", "123456", 6, '0', "123456"},
		{"longer", "1234567", 6, '0', "1234567"},
		{"empty", "", 3, 'X', "XXX"},
		{"different_char", "AB", 5, '_', "___AB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := padLeft(tt.input, tt.minLength, tt.padChar)
			if result != tt.expected {
				t.Errorf("padLeft(%q, %d, %q) = %q, want %q",
					tt.input, tt.minLength, tt.padChar, result, tt.expected)
			}
		})
	}
}

func TestBaseConversionRoundtrip(t *testing.T) {
	alphabets := []string{
		"0123456789",
		"0123456789A",
		"0123456789AB",
		"0123456789ABC",
		"0123456789ABCD",
		"0123456789ABCDE",
		"0123456789ABCDEF",
		"0123456789ABCDEFGHIJKLMNOPQRSTUV",                             // base 32
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", // base 62
	}
	values := []int64{0, 1, 10, 100, 1000, 123456, 999999}

	for _, alphabet := range alphabets {
		for _, value := range values {
			t.Run("", func(t *testing.T) {
				str := formatIntegerInAlphabet(value, alphabet)
				result, err := parseIntegerInAlphabet(str, alphabet)
				if err != nil {
					t.Errorf("roundtrip failed for value=%d, alphabet=%q: %v", value, alphabet, err)
					return
				}
				if result != value {
					t.Errorf("roundtrip mismatch for value=%d, alphabet=%q: got %d via %q",
						value, alphabet, result, str)
				}
			})
		}
	}
}
