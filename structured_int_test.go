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

func TestFormatIntegerToBase(t *testing.T) {
	tests := []struct {
		name     string
		value    int64
		base     int
		expected string
	}{
		{"base10_simple", 123, 10, "123"},
		{"base10_zero", 0, 10, "0"},
		{"base16_simple", 255, 16, "FF"},
		{"base16_larger", 256, 16, "100"},
		{"base12_simple", 11, 12, "B"},
		{"base12_larger", 144, 12, "100"},
		{"base14_simple", 13, 14, "D"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatIntegerToBase(tt.value, tt.base)
			if result != tt.expected {
				t.Errorf("formatIntegerToBase(%d, %d) = %q, want %q",
					tt.value, tt.base, result, tt.expected)
			}
		})
	}
}

func TestParseIntegerFromBase(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		base     int
		expected int64
		wantErr  bool
	}{
		{"base10_simple", "123", 10, 123, false},
		{"base10_zero", "0", 10, 0, false},
		{"base16_simple", "FF", 16, 255, false},
		{"base16_lower", "ff", 16, 255, false},
		{"base16_mixed", "Ff", 16, 255, false},
		{"base16_larger", "100", 16, 256, false},
		{"base12_simple", "B", 12, 11, false},
		{"base12_larger", "100", 12, 144, false},
		{"base14_simple", "D", 14, 13, false},
		{"negative", "-123", 10, -123, false},
		{"invalid_char", "XYZ", 10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseIntegerFromBase(tt.value, tt.base)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseIntegerFromBase(%q, %d) expected error, got nil",
						tt.value, tt.base)
				}
				return
			}
			if err != nil {
				t.Errorf("parseIntegerFromBase(%q, %d) unexpected error: %v",
					tt.value, tt.base, err)
				return
			}
			if result != tt.expected {
				t.Errorf("parseIntegerFromBase(%q, %d) = %d, want %d",
					tt.value, tt.base, result, tt.expected)
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
	bases := []int{10, 11, 12, 13, 14, 15, 16}
	values := []int64{0, 1, 10, 100, 1000, 123456, 999999}

	for _, base := range bases {
		for _, value := range values {
			t.Run("", func(t *testing.T) {
				str := formatIntegerToBase(value, base)
				result, err := parseIntegerFromBase(str, base)
				if err != nil {
					t.Errorf("roundtrip failed for value=%d, base=%d: %v", value, base, err)
					return
				}
				if result != value {
					t.Errorf("roundtrip mismatch for value=%d, base=%d: got %d via %q",
						value, base, result, str)
				}
			})
		}
	}
}
