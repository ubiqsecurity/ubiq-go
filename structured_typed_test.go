package ubiq

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

	// First pass: read every fixture and collect the unique dataset names so we
	// can batch-warm the cache (avoids hitting the 500 req/60s rate limit).
	type fileRecords struct {
		path    string
		records []StructuredTestRecord
	}
	var loaded []fileRecords
	datasetSet := make(map[string]struct{})
	for _, infile := range foundFiles {
		raw, err := os.ReadFile(infile)
		if err != nil {
			t.Skipf("cannot read %s: %v", infile, err)
		}
		var records []StructuredTestRecord
		if err := json.Unmarshal(raw, &records); err != nil {
			t.Skipf("cannot parse %s: %v", infile, err)
		}
		loaded = append(loaded, fileRecords{infile, records})
		for _, r := range records {
			datasetSet[r.Dataset] = struct{}{}
		}
	}

	typedDatasets := make([]string, 0, len(datasetSet))
	for name := range datasetSet {
		typedDatasets = append(typedDatasets, name)
	}
	if err := enc.LoadCache(typedDatasets); err != nil {
		t.Fatalf("LoadCache(enc): %v", err)
	}
	if err := dec.LoadCache(typedDatasets); err != nil {
		t.Fatalf("LoadCache(dec): %v", err)
	}

	ops := make(map[string]*StructuredOperations)

	for _, fr := range loaded {
		t.Logf("Loading file: %v", fr.path)

		for i := range fr.records {
			rec := &fr.records[i]

			op, ok := ops[rec.Dataset]
			if !ok {
				var _op StructuredOperations
				ops[rec.Dataset] = &_op
				op = &_op
				// Warm up the dataset-specific pipeline state with one round trip
				enc.InferredCipher(rec.Dataset, rec.Plaintext, nil)
				dec.InferredDecipher(rec.Dataset, rec.Ciphertext, nil)
			}

			t.Run(fmt.Sprintf("%s/%d", rec.Dataset, i), func(t *testing.T) {
				// Test encryption: plaintext → ciphertext
				beg := time.Now()
				ct, err := enc.InferredCipher(rec.Dataset, rec.Plaintext, nil)
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
				pt, err := dec.InferredDecipher(rec.Dataset, rec.Ciphertext, nil)
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
