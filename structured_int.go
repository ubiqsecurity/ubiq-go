package ubiq

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// integerAlphabet is the alphabet used for integer base conversion (0-9A-F supports up to base 16)
const integerAlphabet = "0123456789ABCDEF"

// CipherInt64 encrypts an int64 value using format-preserving encryption.
// The dataset must be configured with data_type="integer" and size=64.
func (se *StructuredEncryption) CipherInt64(datasetName string, plainInteger int64, tweak []byte) (int64, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return 0, err
	}

	return sC.encryptInt64(dataset, plainInteger, tweak, -1)
}

// CipherInt64ForSearch encrypts an int64 value with all key versions for searchable encryption.
func (se *StructuredEncryption) CipherInt64ForSearch(datasetName string, plainInteger int64, tweak []byte) ([]int64, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return nil, err
	}

	if err := sC.validateIntegerDataset(dataset, 64); err != nil {
		return nil, err
	}

	// Load all keys
	keys, err := sC.fetchAllKeys(datasetName)
	if err != nil {
		return nil, err
	}

	results := make([]int64, 0, len(keys))
	for _, key := range keys {
		cipherInt, err := sC.encryptInt64(dataset, plainInteger, tweak, key.Num)
		if err != nil {
			return nil, err
		}
		results = append(results, cipherInt)
	}

	return results, nil
}

// CipherInt32 encrypts an int32 value using format-preserving encryption.
// The dataset must be configured with data_type="integer" and size=32.
func (se *StructuredEncryption) CipherInt32(datasetName string, plainInteger int32, tweak []byte) (int32, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return 0, err
	}

	result, err := sC.encryptInt32(dataset, plainInteger, tweak, -1)
	if err != nil {
		return 0, err
	}

	return result, nil
}

// CipherInt32ForSearch encrypts an int32 value with all key versions for searchable encryption.
func (se *StructuredEncryption) CipherInt32ForSearch(datasetName string, plainInteger int32, tweak []byte) ([]int32, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return nil, err
	}

	if err := sC.validateIntegerDataset(dataset, 32); err != nil {
		return nil, err
	}

	// Load all keys
	keys, err := sC.fetchAllKeys(datasetName)
	if err != nil {
		return nil, err
	}

	results := make([]int32, 0, len(keys))
	for _, key := range keys {
		cipherInt, err := sC.encryptInt32(dataset, plainInteger, tweak, key.Num)
		if err != nil {
			return nil, err
		}
		results = append(results, cipherInt)
	}

	return results, nil
}

// DecipherInt64 decrypts an int64 value.
func (sd *StructuredDecryption) DecipherInt64(datasetName string, cipherInteger int64, tweak []byte) (int64, error) {
	sC := (*structuredContext)(sd)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return 0, err
	}

	return sC.decryptInt64(dataset, cipherInteger, tweak)
}

// DecipherInt32 decrypts an int32 value.
func (sd *StructuredDecryption) DecipherInt32(datasetName string, cipherInteger int32, tweak []byte) (int32, error) {
	sC := (*structuredContext)(sd)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return 0, err
	}

	return sC.decryptInt32(dataset, cipherInteger, tweak)
}

// validateIntegerDataset validates the dataset is configured for integer encryption.
func (sC *structuredContext) validateIntegerDataset(dataset datasetInfo, expectedSize int64) error {
	if dataset.DataType != "integer" {
		return fmt.Errorf("dataset '%s' is not an 'integer' DataType", dataset.Name)
	}

	if dataset.DataTypeConfig == nil {
		return fmt.Errorf("dataset '%s' is missing data_type_config", dataset.Name)
	}

	if dataset.DataTypeConfig.Size != expectedSize {
		return fmt.Errorf("dataset '%s' does not have a %d-bit DataSize", dataset.Name, expectedSize)
	}

	return nil
}

// encryptInt64 encrypts an int64 using the pipeline.
func (sC *structuredContext) encryptInt64(dataset datasetInfo, plainInteger int64, tweak []byte, keyNumber int) (int64, error) {
	if err := sC.validateIntegerDataset(dataset, 64); err != nil {
		return 0, err
	}

	cfg := dataset.DataTypeConfig

	if plainInteger > cfg.MaxInputIntValue {
		return 0, fmt.Errorf("number must be <= %d", cfg.MaxInputIntValue)
	}

	if plainInteger < cfg.MinInputIntValue {
		return 0, fmt.Errorf("number must be >= %d", cfg.MinInputIntValue)
	}

	// Convert to string and pad to min_input_length
	plainText := formatIntegerForEncryption(plainInteger, dataset.InputLengthMin)

	// Encrypt using the string cipher
	cipherText, err := sC.cipherString(dataset, plainText, tweak, keyNumber)
	if err != nil {
		return 0, err
	}

	// Convert base-X string to base-10 int
	outputBase := len(dataset.OutputCharacterSet)
	cipherInteger, err := parseIntegerFromBase(cipherText, outputBase)
	if err != nil {
		return 0, fmt.Errorf("failed to parse cipher integer: %w", err)
	}

	return cipherInteger, nil
}

// encryptInt32 encrypts an int32 using the pipeline.
func (sC *structuredContext) encryptInt32(dataset datasetInfo, plainInteger int32, tweak []byte, keyNumber int) (int32, error) {
	if err := sC.validateIntegerDataset(dataset, 32); err != nil {
		return 0, err
	}

	cfg := dataset.DataTypeConfig

	if int64(plainInteger) > cfg.MaxInputIntValue {
		return 0, fmt.Errorf("number must be <= %d", cfg.MaxInputIntValue)
	}

	if int64(plainInteger) < cfg.MinInputIntValue {
		return 0, fmt.Errorf("number must be >= %d", cfg.MinInputIntValue)
	}

	// Convert to string and pad to min_input_length
	plainText := formatIntegerForEncryption(int64(plainInteger), dataset.InputLengthMin)

	// Encrypt using the string cipher
	cipherText, err := sC.cipherString(dataset, plainText, tweak, keyNumber)
	if err != nil {
		return 0, err
	}

	// Convert base-X string to base-10 int
	outputBase := len(dataset.OutputCharacterSet)
	cipherInteger, err := parseIntegerFromBase(cipherText, outputBase)
	if err != nil {
		return 0, fmt.Errorf("failed to parse cipher integer: %w", err)
	}

	return int32(cipherInteger), nil
}

// decryptInt64 decrypts an int64 using the pipeline.
func (sC *structuredContext) decryptInt64(dataset datasetInfo, cipherInteger int64, tweak []byte) (int64, error) {
	if err := sC.validateIntegerDataset(dataset, 64); err != nil {
		return 0, err
	}

	isNegative := cipherInteger < 0
	absValue := cipherInteger
	if isNegative {
		absValue = -cipherInteger
	}

	// Convert from base 10 to base-X
	outputBase := len(dataset.OutputCharacterSet)
	cipherText := formatIntegerToBase(absValue, outputBase)

	// Left pad to min_input_length
	cipherText = padLeft(cipherText, dataset.InputLengthMin, '0')

	// Re-add negative sign if needed
	if isNegative {
		cipherText = "-" + cipherText
	}

	// Decrypt using the string decipher
	plainText, err := sC.decipherString(dataset, cipherText, tweak)
	if err != nil {
		return 0, err
	}

	// Convert base-10 string to int
	plainInteger, err := strconv.ParseInt(plainText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse plain integer: %w", err)
	}

	return plainInteger, nil
}

// decryptInt32 decrypts an int32 using the pipeline.
func (sC *structuredContext) decryptInt32(dataset datasetInfo, cipherInteger int32, tweak []byte) (int32, error) {
	if err := sC.validateIntegerDataset(dataset, 32); err != nil {
		return 0, err
	}

	isNegative := cipherInteger < 0
	absValue := int64(cipherInteger)
	if isNegative {
		absValue = -absValue
	}

	// Convert from base 10 to base-X
	outputBase := len(dataset.OutputCharacterSet)
	cipherText := formatIntegerToBase(absValue, outputBase)

	// Left pad to min_input_length
	cipherText = padLeft(cipherText, dataset.InputLengthMin, '0')

	// Re-add negative sign if needed
	if isNegative {
		cipherText = "-" + cipherText
	}

	// Decrypt using the string decipher
	plainText, err := sC.decipherString(dataset, cipherText, tweak)
	if err != nil {
		return 0, err
	}

	// Convert base-10 string to int
	plainInteger, err := strconv.ParseInt(plainText, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse plain integer: %w", err)
	}

	return int32(plainInteger), nil
}

// cipherString is a helper to encrypt a string using the standard Cipher method.
// keyNumber of -1 means use the current key.
func (sC *structuredContext) cipherString(dataset datasetInfo, plainText string, tweak []byte, keyNumber int) (string, error) {
	se := (*StructuredEncryption)(sC)
	if keyNumber >= 0 {
		return se.CipherWithKeyNumber(dataset.Name, plainText, tweak, keyNumber)
	}
	return se.Cipher(dataset.Name, plainText, tweak)
}

// decipherString is a helper to decrypt a string using the standard Decipher method.
func (sC *structuredContext) decipherString(dataset datasetInfo, cipherText string, tweak []byte) (string, error) {
	sd := (*StructuredDecryption)(sC)
	return sd.Cipher(dataset.Name, cipherText, tweak)
}

// formatIntegerForEncryption converts an integer to a string, padded to minLength.
// Handles negative numbers by preserving the sign.
func formatIntegerForEncryption(value int64, minLength int) string {
	isNegative := value < 0
	absValue := value
	if isNegative {
		absValue = -value
	}

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", minLength)
	result := fmt.Sprintf(format, absValue)

	if isNegative {
		result = "-" + result
	}

	return result
}

// formatIntegerToBase converts a non-negative integer to a string in the given base.
func formatIntegerToBase(value int64, base int) string {
	if value == 0 {
		return "0"
	}

	var result strings.Builder
	for value > 0 {
		digit := value % int64(base)
		result.WriteByte(integerAlphabet[digit])
		value /= int64(base)
	}

	// Reverse the string
	s := result.String()
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}

// parseIntegerFromBase parses a string in the given base to an int64.
func parseIntegerFromBase(s string, base int) (int64, error) {
	isNegative := strings.HasPrefix(s, "-")
	if isNegative {
		s = s[1:]
	}

	// Native bases can use strconv
	if base == 2 || base == 8 || base == 10 || base == 16 {
		result, err := strconv.ParseInt(s, base, 64)
		if err != nil {
			return 0, err
		}
		if isNegative {
			return -result, nil
		}
		return result, nil
	}

	// For other bases, parse manually
	var result int64
	s = strings.ToUpper(s)
	for i := 0; i < len(s); i++ {
		digit := strings.IndexByte(integerAlphabet, s[i])
		if digit < 0 || digit >= base {
			return 0, fmt.Errorf("invalid character '%c' for base %d", s[i], base)
		}
		result = result*int64(base) + int64(digit)
	}

	if isNegative {
		return -result, nil
	}
	return result, nil
}

// padLeft pads a string on the left with the specified character to reach minLength.
func padLeft(s string, minLength int, padChar byte) string {
	if len(s) >= minLength {
		return s
	}
	return strings.Repeat(string(padChar), minLength-len(s)) + s
}

// absInt64 returns the absolute value of an int64.
func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// pow calculates base^exp for integers.
func pow(base, exp int) int64 {
	return int64(math.Pow(float64(base), float64(exp)))
}
