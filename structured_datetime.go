package ubiq

import (
	"fmt"
	"time"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline/exec"
)

// CipherDateTime encrypts a time.Time value using format-preserving encryption.
// The dataset must be configured with data_type="datetime".
// The time is converted to seconds from epoch, encrypted, and converted back.
func (se *StructuredEncryption) CipherDateTime(datasetName string, plainDateTime time.Time, tweak []byte) (time.Time, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return time.Time{}, err
	}

	return sC.encryptDateTime(dataset, plainDateTime, tweak, -1)
}

// CipherDateTimeForSearch encrypts a datetime with all key versions for searchable encryption.
func (se *StructuredEncryption) CipherDateTimeForSearch(datasetName string, plainDateTime time.Time, tweak []byte) ([]time.Time, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return nil, err
	}

	if err := sC.validateDateTimeDataset(dataset); err != nil {
		return nil, err
	}

	keys, err := sC.fetchAllKeys(datasetName)
	if err != nil {
		return nil, err
	}

	results := make([]time.Time, 0, len(keys))
	for _, key := range keys {
		cipherTime, err := sC.encryptDateTime(dataset, plainDateTime, tweak, key.Num)
		if err != nil {
			return nil, err
		}
		results = append(results, cipherTime)
	}

	return results, nil
}

// CipherDate encrypts a date (ignoring time component) using format-preserving encryption.
// The dataset must be configured with data_type="date".
// The date is converted to days from epoch, encrypted, and converted back.
func (se *StructuredEncryption) CipherDate(datasetName string, plainDate time.Time, tweak []byte) (time.Time, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return time.Time{}, err
	}

	return sC.encryptDate(dataset, plainDate, tweak, -1)
}

// CipherDateForSearch encrypts a date with all key versions for searchable encryption.
func (se *StructuredEncryption) CipherDateForSearch(datasetName string, plainDate time.Time, tweak []byte) ([]time.Time, error) {
	sC := (*structuredContext)(se)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return nil, err
	}

	if err := sC.validateDateDataset(dataset); err != nil {
		return nil, err
	}

	keys, err := sC.fetchAllKeys(datasetName)
	if err != nil {
		return nil, err
	}

	results := make([]time.Time, 0, len(keys))
	for _, key := range keys {
		cipherTime, err := sC.encryptDate(dataset, plainDate, tweak, key.Num)
		if err != nil {
			return nil, err
		}
		results = append(results, cipherTime)
	}

	return results, nil
}

// DecipherDateTime decrypts a datetime value.
func (sd *StructuredDecryption) DecipherDateTime(datasetName string, cipherDateTime time.Time, tweak []byte) (time.Time, error) {
	sC := (*structuredContext)(sd)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return time.Time{}, err
	}

	return sC.decryptDateTime(dataset, cipherDateTime, tweak)
}

// DecipherDate decrypts a date value.
func (sd *StructuredDecryption) DecipherDate(datasetName string, cipherDate time.Time, tweak []byte) (time.Time, error) {
	sC := (*structuredContext)(sd)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return time.Time{}, err
	}

	return sC.decryptDate(dataset, cipherDate, tweak)
}

// GetKeyNumberDateTime returns the key number (key version) that the
// given datetime ciphertext was encrypted with, without decrypting it.
// The dataset must be configured with data_type="datetime".
//
// Only the dataset definition is required, which is typically served
// from the local cache. No encryption key is fetched and no usage
// event is reported.
func (sd *StructuredDecryption) GetKeyNumberDateTime(datasetName string, cipherDateTime time.Time) (int, error) {
	sC := (*structuredContext)(sd)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return 0, err
	}

	if err := sC.validateDateTimeDataset(dataset); err != nil {
		return 0, err
	}

	cipherText, err := dateTimeCipherText(dataset, cipherDateTime)
	if err != nil {
		return 0, err
	}

	return exec.DecodeKeyNumber(toPipelineDatasetInfo(dataset), cipherText)
}

// GetKeyNumberDate returns the key number (key version) that the given
// date ciphertext was encrypted with, without decrypting it. The date
// must be UTC and the dataset must be configured with data_type="date".
//
// Only the dataset definition is required, which is typically served
// from the local cache. No encryption key is fetched and no usage
// event is reported.
func (sd *StructuredDecryption) GetKeyNumberDate(datasetName string, cipherDate time.Time) (int, error) {
	sC := (*structuredContext)(sd)

	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return 0, err
	}

	if err := sC.validateDateDataset(dataset); err != nil {
		return 0, err
	}

	cipherText, err := dateCipherText(dataset, cipherDate)
	if err != nil {
		return 0, err
	}

	return exec.DecodeKeyNumber(toPipelineDatasetInfo(dataset), cipherText)
}

// validateDateTimeDataset validates the dataset is configured for datetime encryption.
func (sC *structuredContext) validateDateTimeDataset(dataset datasetInfo) error {
	if dataset.DataType != "datetime" {
		return fmt.Errorf("dataset '%s' is not a 'datetime' DataType", dataset.Name)
	}

	if dataset.DataTypeConfig == nil {
		return fmt.Errorf("dataset '%s' is missing data_type_config", dataset.Name)
	}

	return nil
}

// validateDateDataset validates the dataset is configured for date encryption.
func (sC *structuredContext) validateDateDataset(dataset datasetInfo) error {
	if dataset.DataType != "date" {
		return fmt.Errorf("dataset '%s' is not a 'date' DataType", dataset.Name)
	}

	if dataset.DataTypeConfig == nil {
		return fmt.Errorf("dataset '%s' is missing data_type_config", dataset.Name)
	}

	return nil
}

// parseEpoch parses the epoch from dataset config. Returns Unix epoch if not specified.
func parseEpoch(epochStr string) (time.Time, error) {
	if epochStr == "" {
		return time.Unix(0, 0).UTC(), nil
	}

	// Try RFC3339 format first
	t, err := time.Parse(time.RFC3339, epochStr)
	if err == nil {
		return t.UTC(), nil
	}

	// Try date-only format
	t, err = time.Parse("2006-01-02", epochStr)
	if err == nil {
		return t.UTC(), nil
	}

	// Try datetime without timezone
	t, err = time.Parse("2006-01-02T15:04:05", epochStr)
	if err == nil {
		return t.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("unable to parse epoch: %s", epochStr)
}

// parseDate parses a date string in various formats.
func parseDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, nil
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// encryptDateTime encrypts a datetime using the pipeline.
func (sC *structuredContext) encryptDateTime(dataset datasetInfo, plainDateTime time.Time, tweak []byte, keyNumber int) (time.Time, error) {
	if err := sC.validateDateTimeDataset(dataset); err != nil {
		return time.Time{}, err
	}

	cfg := dataset.DataTypeConfig

	// Convert to UTC
	utcPlainDateTime := plainDateTime.UTC()

	// Track offset to preserve timezone kind
	utcOffset := utcPlainDateTime.Sub(plainDateTime)

	// Parse epoch
	epoch, err := parseEpoch(cfg.Epoch)
	if err != nil {
		return time.Time{}, err
	}

	// Validate against min/max dates if specified
	if cfg.MaxInputDate != "" {
		maxDate, err := parseDate(cfg.MaxInputDate)
		if err != nil {
			return time.Time{}, err
		}
		if utcPlainDateTime.After(maxDate) {
			return time.Time{}, fmt.Errorf("plainDateTime must be <= %v", maxDate)
		}
	}

	if cfg.MinInputDate != "" {
		minDate, err := parseDate(cfg.MinInputDate)
		if err != nil {
			return time.Time{}, err
		}
		if utcPlainDateTime.Before(minDate) {
			return time.Time{}, fmt.Errorf("plainDateTime must be >= %v", minDate)
		}
	}

	// Convert datetime to seconds from epoch using Unix seconds to avoid time.Duration overflow
	secondsFromEpoch := utcPlainDateTime.Unix() - epoch.Unix()

	// Track if negative
	isNegative := secondsFromEpoch < 0
	absSeconds := secondsFromEpoch
	if isNegative {
		absSeconds = -secondsFromEpoch
	}

	// Format in the dataset's input alphabet and pad to min_input_length
	plainText := formatIntegerInAlphabet(absSeconds, dataset.InputCharacterSet)
	plainText = padLeft(plainText, dataset.InputLengthMin, dataset.InputCharacterSet[0])

	// Re-add negative sign
	if isNegative {
		plainText = "-" + plainText
	}

	// Encrypt using the string cipher
	cipherText, err := sC.cipherString(dataset, plainText, tweak, keyNumber)
	if err != nil {
		return time.Time{}, err
	}

	// Convert ciphertext from the dataset's output alphabet to int64
	encryptedSeconds, err := parseIntegerInAlphabet(cipherText, dataset.OutputCharacterSet)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse encrypted seconds: %w", err)
	}

	// Convert encrypted seconds back to datetime using Unix to avoid time.Duration overflow
	encryptedDateTime := time.Unix(epoch.Unix()+encryptedSeconds, 0).UTC()

	// Apply UTC offset to match original timezone
	localEncryptedDateTime := encryptedDateTime.Add(-utcOffset)

	return localEncryptedDateTime, nil
}

// dateTimeCipherText converts a cipher datetime back to the string form
// produced by the string cipher: the seconds from the dataset's epoch
// formatted in the output alphabet, left padded to min_input_length,
// with the sign re-applied.
func dateTimeCipherText(dataset datasetInfo, cipherDateTime time.Time) (string, error) {
	// Parse epoch
	epoch, err := parseEpoch(dataset.DataTypeConfig.Epoch)
	if err != nil {
		return "", err
	}

	// Convert datetime to seconds from epoch using Unix seconds to avoid time.Duration overflow
	cipherSecondsFromEpoch := cipherDateTime.UTC().Unix() - epoch.Unix()

	isNegative := cipherSecondsFromEpoch < 0
	absSeconds := cipherSecondsFromEpoch
	if isNegative {
		absSeconds = -cipherSecondsFromEpoch
	}

	// Format in the dataset's output alphabet
	cipherText := formatIntegerInAlphabet(absSeconds, dataset.OutputCharacterSet)

	// Left pad to min_input_length
	cipherText = padLeft(cipherText, dataset.InputLengthMin, dataset.OutputCharacterSet[0])

	// Re-add negative sign if needed
	if isNegative {
		cipherText = "-" + cipherText
	}

	return cipherText, nil
}

// decryptDateTime decrypts a datetime using the pipeline.
func (sC *structuredContext) decryptDateTime(dataset datasetInfo, cipherDateTime time.Time, tweak []byte) (time.Time, error) {
	if err := sC.validateDateTimeDataset(dataset); err != nil {
		return time.Time{}, err
	}

	cfg := dataset.DataTypeConfig

	// Convert to UTC
	utcCipherDateTime := cipherDateTime.UTC()

	// Track offset
	utcOffset := utcCipherDateTime.Sub(cipherDateTime)

	// Parse epoch
	epoch, err := parseEpoch(cfg.Epoch)
	if err != nil {
		return time.Time{}, err
	}

	cipherText, err := dateTimeCipherText(dataset, cipherDateTime)
	if err != nil {
		return time.Time{}, err
	}

	// Decrypt using the string decipher
	plainText, err := sC.decipherString(dataset, cipherText, tweak)
	if err != nil {
		return time.Time{}, err
	}

	// Parse the plaintext as seconds in the dataset's input alphabet
	plainSeconds, err := parseIntegerInAlphabet(plainText, dataset.InputCharacterSet)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse plain seconds: %w", err)
	}

	// Convert decrypted seconds back to datetime using Unix to avoid time.Duration overflow
	plainDateTime := time.Unix(epoch.Unix()+plainSeconds, 0).UTC()

	// Apply UTC offset
	localPlainDateTime := plainDateTime.Add(-utcOffset)

	return localPlainDateTime, nil
}

// encryptDate encrypts a date using the pipeline.
func (sC *structuredContext) encryptDate(dataset datasetInfo, plainDate time.Time, tweak []byte, keyNumber int) (time.Time, error) {
	if err := sC.validateDateDataset(dataset); err != nil {
		return time.Time{}, err
	}

	cfg := dataset.DataTypeConfig

	// Must be UTC
	if plainDate.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("plainDate must be UTC")
	}

	// Truncate to date only
	utcPlainDate := time.Date(plainDate.Year(), plainDate.Month(), plainDate.Day(), 0, 0, 0, 0, time.UTC)

	// Parse epoch
	epoch, err := parseEpoch(cfg.Epoch)
	if err != nil {
		return time.Time{}, err
	}
	epochDate := time.Date(epoch.Year(), epoch.Month(), epoch.Day(), 0, 0, 0, 0, time.UTC)

	// Validate against min/max dates if specified
	if cfg.MaxInputDate != "" {
		maxDate, err := parseDate(cfg.MaxInputDate)
		if err != nil {
			return time.Time{}, err
		}
		maxDateOnly := time.Date(maxDate.Year(), maxDate.Month(), maxDate.Day(), 0, 0, 0, 0, time.UTC)
		if utcPlainDate.After(maxDateOnly) {
			return time.Time{}, fmt.Errorf("plainDate must be <= %v", maxDateOnly)
		}
	}

	if cfg.MinInputDate != "" {
		minDate, err := parseDate(cfg.MinInputDate)
		if err != nil {
			return time.Time{}, err
		}
		minDateOnly := time.Date(minDate.Year(), minDate.Month(), minDate.Day(), 0, 0, 0, 0, time.UTC)
		if utcPlainDate.Before(minDateOnly) {
			return time.Time{}, fmt.Errorf("plainDate must be >= %v", minDateOnly)
		}
	}

	// Convert date to days from epoch using Unix seconds to avoid time.Duration overflow
	// (time.Duration is int64 nanoseconds, max ~292 years; dates can span thousands of years)
	daysFromEpoch := (utcPlainDate.Unix() - epochDate.Unix()) / 86400

	// Track if negative
	isNegative := daysFromEpoch < 0
	absDays := daysFromEpoch
	if isNegative {
		absDays = -daysFromEpoch
	}

	// Format in the dataset's input alphabet and pad to min_input_length
	plainText := formatIntegerInAlphabet(absDays, dataset.InputCharacterSet)
	plainText = padLeft(plainText, dataset.InputLengthMin, dataset.InputCharacterSet[0])

	// Re-add negative sign
	if isNegative {
		plainText = "-" + plainText
	}

	cipherText, err := sC.cipherString(dataset, plainText, tweak, keyNumber)
	if err != nil {
		return time.Time{}, err
	}

	// Convert ciphertext from the dataset's output alphabet to int64
	encryptedDays, err := parseIntegerInAlphabet(cipherText, dataset.OutputCharacterSet)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse encrypted days: %w", err)
	}

	// Convert encrypted days back to date
	encryptedDate := epochDate.AddDate(0, 0, int(encryptedDays))

	return encryptedDate, nil
}

// dateCipherText converts a cipher date back to the string form produced
// by the string cipher: the days from the dataset's epoch formatted in
// the output alphabet, left padded to min_input_length, with the sign
// re-applied. The date must be UTC.
func dateCipherText(dataset datasetInfo, cipherDate time.Time) (string, error) {
	// Must be UTC
	if cipherDate.Location() != time.UTC {
		return "", fmt.Errorf("cipherDate must be UTC")
	}

	// Parse epoch
	epoch, err := parseEpoch(dataset.DataTypeConfig.Epoch)
	if err != nil {
		return "", err
	}
	epochDate := time.Date(epoch.Year(), epoch.Month(), epoch.Day(), 0, 0, 0, 0, time.UTC)

	// Convert date to days from epoch using Unix seconds to avoid time.Duration overflow
	cipherDaysFromEpoch := (cipherDate.Unix() - epochDate.Unix()) / 86400

	isNegative := cipherDaysFromEpoch < 0
	absDays := cipherDaysFromEpoch
	if isNegative {
		absDays = -cipherDaysFromEpoch
	}

	// Format in the dataset's output alphabet
	cipherText := formatIntegerInAlphabet(absDays, dataset.OutputCharacterSet)

	// Left pad to min_input_length
	cipherText = padLeft(cipherText, dataset.InputLengthMin, dataset.OutputCharacterSet[0])

	// Re-add negative sign if needed
	if isNegative {
		cipherText = "-" + cipherText
	}

	return cipherText, nil
}

// decryptDate decrypts a date using the pipeline.
func (sC *structuredContext) decryptDate(dataset datasetInfo, cipherDate time.Time, tweak []byte) (time.Time, error) {
	if err := sC.validateDateDataset(dataset); err != nil {
		return time.Time{}, err
	}

	cfg := dataset.DataTypeConfig

	// Parse epoch
	epoch, err := parseEpoch(cfg.Epoch)
	if err != nil {
		return time.Time{}, err
	}
	epochDate := time.Date(epoch.Year(), epoch.Month(), epoch.Day(), 0, 0, 0, 0, time.UTC)

	cipherText, err := dateCipherText(dataset, cipherDate)
	if err != nil {
		return time.Time{}, err
	}

	// Decrypt using the string decipher
	plainText, err := sC.decipherString(dataset, cipherText, tweak)
	if err != nil {
		return time.Time{}, err
	}

	// Parse the plaintext as days in the dataset's input alphabet
	plainDays, err := parseIntegerInAlphabet(plainText, dataset.InputCharacterSet)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse plain days: %w", err)
	}

	// Convert decrypted days back to date
	plainDate := epochDate.AddDate(0, 0, int(plainDays))

	return plainDate, nil
}
