package ubiq

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// parseDateTestString parses a date string from the test data JSON.
// DATE format: "2677-05-16T00:00Z" (no seconds)
func parseDateTestString(s string) (time.Time, error) {
	// Insert :00 seconds before Z to make valid RFC3339
	s = strings.Replace(s, "T00:00Z", "T00:00:00Z", 1)
	return time.Parse(time.RFC3339, s)
}

// formatDateTestString formats a time.Time back to the DATE test data format.
// Output: "2677-05-16T00:00Z"
func formatDateTestString(t time.Time) string {
	return t.UTC().Format("2006-01-02") + "T00:00Z"
}

// parseDateTimeTestString parses a datetime string from the test data JSON.
// DATETIME format: "2195-04-02T23:24:40Z"
func parseDateTimeTestString(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// formatDateTimeTestString formats a time.Time back to the DATETIME test data format.
// Output: "2195-04-02T23:24:40Z"
func formatDateTimeTestString(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// inferredEncrypt encrypts a plaintext string using the appropriate typed API
// based on the dataset name, and returns the ciphertext as a string.
func inferredEncrypt(enc *StructuredEncryption, dataset, plainText string) (string, error) {
	switch dataset {
	case "integer32":
		v, err := strconv.ParseInt(plainText, 10, 32)
		if err != nil {
			return "", fmt.Errorf("parse integer32 plaintext %q: %w", plainText, err)
		}
		ct, err := enc.CipherInt32(dataset, int32(v), nil)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(int64(ct), 10), nil

	case "integer64":
		v, err := strconv.ParseInt(plainText, 10, 64)
		if err != nil {
			return "", fmt.Errorf("parse integer64 plaintext %q: %w", plainText, err)
		}
		ct, err := enc.CipherInt64(dataset, v, nil)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(ct, 10), nil

	case "date":
		v, err := parseDateTestString(plainText)
		if err != nil {
			return "", fmt.Errorf("parse date plaintext %q: %w", plainText, err)
		}
		ct, err := enc.CipherDate(dataset, v, nil)
		if err != nil {
			return "", err
		}
		return formatDateTestString(ct), nil

	case "datetime":
		v, err := parseDateTimeTestString(plainText)
		if err != nil {
			return "", fmt.Errorf("parse datetime plaintext %q: %w", plainText, err)
		}
		ct, err := enc.CipherDateTime(dataset, v, nil)
		if err != nil {
			return "", err
		}
		return formatDateTimeTestString(ct), nil

	default:
		// String-based datasets (generic_string_*, token*, etc.)
		return enc.Cipher(dataset, plainText, nil)
	}
}

// inferredDecrypt decrypts a ciphertext string using the appropriate typed API
// based on the dataset name, and returns the plaintext as a string.
func inferredDecrypt(dec *StructuredDecryption, dataset, cipherText string) (string, error) {
	switch dataset {
	case "integer32":
		v, err := strconv.ParseInt(cipherText, 10, 32)
		if err != nil {
			return "", fmt.Errorf("parse integer32 ciphertext %q: %w", cipherText, err)
		}
		pt, err := dec.DecipherInt32(dataset, int32(v), nil)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(int64(pt), 10), nil

	case "integer64":
		v, err := strconv.ParseInt(cipherText, 10, 64)
		if err != nil {
			return "", fmt.Errorf("parse integer64 ciphertext %q: %w", cipherText, err)
		}
		pt, err := dec.DecipherInt64(dataset, v, nil)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(pt, 10), nil

	case "date":
		v, err := parseDateTestString(cipherText)
		if err != nil {
			return "", fmt.Errorf("parse date ciphertext %q: %w", cipherText, err)
		}
		pt, err := dec.DecipherDate(dataset, v, nil)
		if err != nil {
			return "", err
		}
		return formatDateTestString(pt), nil

	case "datetime":
		v, err := parseDateTimeTestString(cipherText)
		if err != nil {
			return "", fmt.Errorf("parse datetime ciphertext %q: %w", cipherText, err)
		}
		pt, err := dec.DecipherDateTime(dataset, v, nil)
		if err != nil {
			return "", err
		}
		return formatDateTimeTestString(pt), nil

	default:
		return dec.Cipher(dataset, cipherText, nil)
	}
}

// TestStructuredTypedFiles loads test vector JSON files from load_time/DATA/types/
// and tests encrypt/decrypt for all data types (int32, int64, date, datetime, string, token).
// This validates cross-SDK compatibility with the .NET implementation.
//
// Set UBIQ_TEST_TYPES_DIR to override the test data directory.
// Defaults to "testdata/ubiq-test-data/prod/dataset_types/" if not set.
func TestStructuredTypedFiles(t *testing.T) {
	typesDir := os.Getenv("UBIQ_TEST_TYPES_DIR")
	if typesDir == "" {
		typesDir = "testdata/ubiq-test-data/prod/dataset_types/"
	}

	foundFiles, _ := filepath.Glob(filepath.Join(typesDir, "*.json"))
	if len(foundFiles) == 0 {
		t.Skipf("no test data files found in %s (set UBIQ_TEST_TYPES_DIR)", typesDir)
	}

	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	// Pre-load all typed datasets into cache to avoid per-request API calls
	// and prevent hitting the rate limit (500 req/60s)
	typedDatasets := []string{"integer32", "integer64", "date", "datetime", "generic_string", "generic_string_32", "generic_string_64", "token64", "token128"}
	if err := enc.LoadCache(typedDatasets); err != nil {
		t.Fatalf("LoadCache(enc): %v", err)
	}
	if err := dec.LoadCache(typedDatasets); err != nil {
		t.Fatalf("LoadCache(dec): %v", err)
	}

	var ops map[string]*StructuredOperations = make(map[string]*StructuredOperations)

	for _, infile := range foundFiles {
		t.Logf("Loading file: %v", infile)

		file, err := os.Open(infile)
		if err != nil {
			t.Skipf("cannot open %s: %v", infile, err)
		}
		defer file.Close()

		raw, err := io.ReadAll(file)
		if err != nil {
			t.Skipf("cannot read %s: %v", infile, err)
		}

		var records []StructuredTestRecord
		err = json.Unmarshal(raw, &records)
		if err != nil {
			t.Skipf("cannot parse %s: %v", infile, err)
		}

		for i := range records {
			rec := &records[i]

			op, ok := ops[rec.Dataset]
			if !ok {
				var _op StructuredOperations
				ops[rec.Dataset] = &_op
				op = &_op
				// Warm up cache with one encrypt/decrypt
				inferredEncrypt(enc, rec.Dataset, rec.Plaintext)
				inferredDecrypt(dec, rec.Dataset, rec.Ciphertext)
			}

			t.Run(fmt.Sprintf("%s/%d", rec.Dataset, i), func(t *testing.T) {
				// Test encryption: plaintext → ciphertext
				beg := time.Now()
				ct, err := inferredEncrypt(enc, rec.Dataset, rec.Plaintext)
				if err != nil {
					t.Fatalf("encrypt(%s, %q): %v", rec.Dataset, rec.Plaintext, err)
				}
				if ct != rec.Ciphertext {
					t.Fatalf("encrypt(%s, %q): got %q, want %q",
						rec.Dataset, rec.Plaintext, ct, rec.Ciphertext)
				}
				op.perf.Duration.Encrypt += time.Since(beg)

				// Test decryption: ciphertext → plaintext
				beg = time.Now()
				pt, err := inferredDecrypt(dec, rec.Dataset, rec.Ciphertext)
				if err != nil {
					t.Fatalf("decrypt(%s, %q): %v", rec.Dataset, rec.Ciphertext, err)
				}
				if pt != rec.Plaintext {
					t.Fatalf("decrypt(%s, %q): got %q, want %q",
						rec.Dataset, rec.Ciphertext, pt, rec.Plaintext)
				}
				op.perf.Duration.Decrypt += time.Since(beg)

				op.perf.Count++
			})
		}
	}

	// Print performance summary
	for dset, op := range ops {
		if op.perf.Count == 0 {
			continue
		}
		t.Logf("%s: %d records", dset, op.perf.Count)
		t.Logf("\tencrypt: %v / per",
			time.Duration(int64(op.perf.Duration.Encrypt)/int64(op.perf.Count)))
		t.Logf("\tdecrypt: %v / per",
			time.Duration(int64(op.perf.Duration.Decrypt)/int64(op.perf.Count)))
	}
}

// --- Individual Roundtrip Tests ---

func TestCipherInt32Roundtrip(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"integer32"})
	dec.LoadCache([]string{"integer32"})

	values := []int32{0, 1, -1, 151223, -12312, 99999999, -99999999}

	for _, v := range values {
		t.Run(fmt.Sprintf("%d", v), func(t *testing.T) {
			ct, err := enc.CipherInt32("integer32", v, nil)
			if err != nil {
				t.Fatalf("CipherInt32(%d): %v", v, err)
			}

			pt, err := dec.DecipherInt32("integer32", ct, nil)
			if err != nil {
				t.Fatalf("DecipherInt32(%d): %v", ct, err)
			}

			if pt != v {
				t.Fatalf("roundtrip failed: %d → %d → %d", v, ct, pt)
			}
		})
	}
}

func TestCipherInt64Roundtrip(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"integer64"})
	dec.LoadCache([]string{"integer64"})

	values := []int64{0, 1, -1, 8755166923889500, -3723142020174110, 41515900698569}

	for _, v := range values {
		t.Run(fmt.Sprintf("%d", v), func(t *testing.T) {
			ct, err := enc.CipherInt64("integer64", v, nil)
			if err != nil {
				t.Fatalf("CipherInt64(%d): %v", v, err)
			}

			pt, err := dec.DecipherInt64("integer64", ct, nil)
			if err != nil {
				t.Fatalf("DecipherInt64(%d): %v", ct, err)
			}

			if pt != v {
				t.Fatalf("roundtrip failed: %d → %d → %d", v, ct, pt)
			}
		})
	}
}

func TestCipherDateRoundtrip(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"date"})
	dec.LoadCache([]string{"date"})

	dates := []time.Time{
		time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1653, 2, 10, 0, 0, 0, 0, time.UTC),
		time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC),
		time.Date(2738, 11, 28, 0, 0, 0, 0, time.UTC),
	}

	for _, v := range dates {
		t.Run(v.Format("2006-01-02"), func(t *testing.T) {
			ct, err := enc.CipherDate("date", v, nil)
			if err != nil {
				t.Fatalf("CipherDate(%v): %v", v, err)
			}

			pt, err := dec.DecipherDate("date", ct, nil)
			if err != nil {
				t.Fatalf("DecipherDate(%v): %v", ct, err)
			}

			if !pt.Equal(v) {
				t.Fatalf("roundtrip failed: %v → %v → %v", v, ct, pt)
			}
		})
	}
}

func TestCipherDateTimeRoundtrip(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"datetime"})
	dec.LoadCache([]string{"datetime"})

	datetimes := []time.Time{
		time.Date(2001, 1, 10, 3, 4, 5, 0, time.UTC),
		time.Date(1969, 12, 30, 15, 0, 0, 0, time.UTC),
		time.Date(1653, 2, 10, 6, 13, 21, 0, time.UTC),
		time.Date(2286, 11, 20, 17, 46, 39, 0, time.UTC),
	}

	for _, v := range datetimes {
		t.Run(v.Format(time.RFC3339), func(t *testing.T) {
			ct, err := enc.CipherDateTime("datetime", v, nil)
			if err != nil {
				t.Fatalf("CipherDateTime(%v): %v", v, err)
			}

			pt, err := dec.DecipherDateTime("datetime", ct, nil)
			if err != nil {
				t.Fatalf("DecipherDateTime(%v): %v", ct, err)
			}

			if !pt.Equal(v) {
				t.Fatalf("roundtrip failed: %v → %v → %v", v, ct, pt)
			}
		})
	}
}

// --- ForSearch Tests ---

func TestCipherInt32ForSearch(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"integer32"})
	dec.LoadCache([]string{"integer32"})

	plainInt := int32(42)

	allCiphers, err := enc.CipherInt32ForSearch("integer32", plainInt, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(allCiphers) < 1 {
		t.Fatal("expected at least 1 cipher for search")
	}

	// Verify all ciphers decrypt to the same plaintext
	for i, ct := range allCiphers {
		pt, err := dec.DecipherInt32("integer32", ct, nil)
		if err != nil {
			t.Fatalf("DecipherInt32 cipher[%d]=%d: %v", i, ct, err)
		}
		if pt != plainInt {
			t.Fatalf("cipher[%d]=%d decrypted to %d, want %d", i, ct, pt, plainInt)
		}
	}

	// Verify the most recent cipher is in the search results
	mostRecent, err := enc.CipherInt32("integer32", plainInt, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ct := range allCiphers {
		if ct == mostRecent {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recent cipher %d not found in search results", mostRecent)
	}
}

func TestCipherInt64ForSearch(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"integer64"})
	dec.LoadCache([]string{"integer64"})

	plainInt := int64(8755166923889500)

	allCiphers, err := enc.CipherInt64ForSearch("integer64", plainInt, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(allCiphers) < 1 {
		t.Fatal("expected at least 1 cipher for search")
	}

	for i, ct := range allCiphers {
		pt, err := dec.DecipherInt64("integer64", ct, nil)
		if err != nil {
			t.Fatalf("DecipherInt64 cipher[%d]=%d: %v", i, ct, err)
		}
		if pt != plainInt {
			t.Fatalf("cipher[%d]=%d decrypted to %d, want %d", i, ct, pt, plainInt)
		}
	}

	mostRecent, err := enc.CipherInt64("integer64", plainInt, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ct := range allCiphers {
		if ct == mostRecent {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recent cipher %d not found in search results", mostRecent)
	}
}

func TestCipherDateForSearch(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"date"})
	dec.LoadCache([]string{"date"})

	plainDate := time.Date(1653, 2, 10, 0, 0, 0, 0, time.UTC)

	allCiphers, err := enc.CipherDateForSearch("date", plainDate, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(allCiphers) < 1 {
		t.Fatal("expected at least 1 cipher for search")
	}

	for i, ct := range allCiphers {
		pt, err := dec.DecipherDate("date", ct, nil)
		if err != nil {
			t.Fatalf("DecipherDate cipher[%d]=%v: %v", i, ct, err)
		}
		if !pt.Equal(plainDate) {
			t.Fatalf("cipher[%d]=%v decrypted to %v, want %v", i, ct, pt, plainDate)
		}
	}

	mostRecent, err := enc.CipherDate("date", plainDate, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ct := range allCiphers {
		if ct.Equal(mostRecent) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recent cipher %v not found in search results", mostRecent)
	}
}

func TestCipherDateTimeForSearch(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"datetime"})
	dec.LoadCache([]string{"datetime"})

	plainDateTime := time.Date(2286, 11, 20, 17, 46, 39, 0, time.UTC)

	allCiphers, err := enc.CipherDateTimeForSearch("datetime", plainDateTime, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(allCiphers) < 1 {
		t.Fatal("expected at least 1 cipher for search")
	}

	for i, ct := range allCiphers {
		pt, err := dec.DecipherDateTime("datetime", ct, nil)
		if err != nil {
			t.Fatalf("DecipherDateTime cipher[%d]=%v: %v", i, ct, err)
		}
		if !pt.Equal(plainDateTime) {
			t.Fatalf("cipher[%d]=%v decrypted to %v, want %v", i, ct, pt, plainDateTime)
		}
	}

	mostRecent, err := enc.CipherDateTime("datetime", plainDateTime, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ct := range allCiphers {
		if ct.Equal(mostRecent) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recent cipher %v not found in search results", mostRecent)
	}
}

func TestCipherGenericStringForSearch(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"generic_string_32"})
	dec.LoadCache([]string{"generic_string_32"})

	plainText := "abcdefghij"

	allCiphers, err := enc.CipherForSearch("generic_string_32", plainText, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(allCiphers) < 2 {
		t.Fatalf("expected at least 2 ciphers for search, got %d", len(allCiphers))
	}

	for i, ct := range allCiphers {
		pt, err := dec.Cipher("generic_string_32", ct, nil)
		if err != nil {
			t.Fatalf("Decipher cipher[%d]=%q: %v", i, ct, err)
		}
		if pt != plainText {
			t.Fatalf("cipher[%d]=%q decrypted to %q, want %q", i, ct, pt, plainText)
		}
	}

	mostRecent, err := enc.Cipher("generic_string_32", plainText, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ct := range allCiphers {
		if ct == mostRecent {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recent cipher %q not found in search results", mostRecent)
	}
}

func TestCipherTokenForSearch(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"token64"})
	dec.LoadCache([]string{"token64"})

	plainText := "hello"

	allCiphers, err := enc.CipherForSearch("token64", plainText, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(allCiphers) < 2 {
		t.Fatalf("expected at least 2 ciphers for search, got %d", len(allCiphers))
	}

	for i, ct := range allCiphers {
		pt, err := dec.Cipher("token64", ct, nil)
		if err != nil {
			t.Fatalf("Decipher cipher[%d]=%q: %v", i, ct, err)
		}
		if pt != plainText {
			t.Fatalf("cipher[%d]=%q decrypted to %q, want %q", i, ct, pt, plainText)
		}
	}

	mostRecent, err := enc.Cipher("token64", plainText, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ct := range allCiphers {
		if ct == mostRecent {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recent cipher %q not found in search results", mostRecent)
	}
}

func TestCipherGenericStringNoSuffixForSearch(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	enc.LoadCache([]string{"generic_string"})
	dec.LoadCache([]string{"generic_string"})

	plainText := "abcdefghij"

	allCiphers, err := enc.CipherForSearch("generic_string", plainText, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(allCiphers) < 2 {
		t.Fatalf("expected at least 2 ciphers for search, got %d", len(allCiphers))
	}

	for i, ct := range allCiphers {
		pt, err := dec.Cipher("generic_string", ct, nil)
		if err != nil {
			t.Fatalf("Decipher cipher[%d]=%q: %v", i, ct, err)
		}
		if pt != plainText {
			t.Fatalf("cipher[%d]=%q decrypted to %q, want %q", i, ct, pt, plainText)
		}
	}

	mostRecent, err := enc.Cipher("generic_string", plainText, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ct := range allCiphers {
		if ct == mostRecent {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recent cipher %q not found in search results", mostRecent)
	}
}

// --- Boundary / Error Tests ---

func TestCipherInt32OutOfRange(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	enc.LoadCache([]string{"integer32"})

	// These values should exceed the INT32 dataset's configured range
	outOfRange := []int32{
		int32(100000000),  // > 99999999
		int32(-100000000), // < -99999999
	}

	for _, v := range outOfRange {
		t.Run(fmt.Sprintf("%d", v), func(t *testing.T) {
			_, err := enc.CipherInt32("integer32", v, nil)
			if err == nil {
				t.Fatalf("CipherInt32(%d) expected error for out-of-range value", v)
			}
			t.Logf("CipherInt32(%d) correctly returned: %v", v, err)
		})
	}
}

func TestCipherDateNonUTC(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	enc.LoadCache([]string{"date"})

	// Non-UTC date should be rejected
	loc, _ := time.LoadLocation("America/New_York")
	nonUTCDate := time.Date(2024, 6, 15, 0, 0, 0, 0, loc)

	_, err = enc.CipherDate("date", nonUTCDate, nil)
	if err == nil {
		t.Fatal("CipherDate with non-UTC date should return error")
	}
	t.Logf("CipherDate(non-UTC) correctly returned: %v", err)
}
