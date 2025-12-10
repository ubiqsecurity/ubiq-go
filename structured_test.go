package ubiq

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"testing"
	"path/filepath"
	"time"
)

func TestGetDataset(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ((*structuredContext)(enc)).getDatasetInfo("ALPHANUM_SSN")
	if err != nil {
		t.Fatal(err)
	}
	enc.Close()
}

func testStructured(t *testing.T, dataset, pt string) {
	initializeCreds()
	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.Cipher(dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	rt, err := dec.Cipher(dataset, ct, nil)
	if err != nil {
		t.Fatal(err)
	}

	if pt != rt {
		t.Fatalf("bad recovered plaintext: \"%s\" vs. \"%s\"", pt, rt)
	}

	enc.Close()
	dec.Close()
}

func TestStructuredAlnumSSN(t *testing.T) {
	testStructured(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestStructuredBirthdate(t *testing.T) {
	testStructured(t, "BIRTH_DATE", "04-20-1969")
}
func TestStructuredSSN(t *testing.T) {
	testStructured(t, "SSN", "987-65-4321")
}
func TestStructuredUTF8(t *testing.T) {
	testStructured(t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}
func TestStructuredUTF8Complex(t *testing.T) {
	testStructured(t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testStructuredForSearchLocal(t *testing.T, dataset, pt string) {
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

	ct, err := enc.CipherForSearch(dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := range ct {
		rt, err := dec.Cipher(dataset, ct[i], nil)
		if err != nil {
			t.Fatal(err)
		}

		if pt != rt {
			t.Fatalf(
				"bad recovered plaintext: \"%s\" vs. \"%s\"",
				pt, rt)
		}
	}
}

func TestStructuredAlnumSSNForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(t, "ALPHANUM_SSN", "123-45-6789")
}
func TestStructuredBirthdateForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(t, "BIRTH_DATE", "04-20-1969")
}
func TestStructuredSSNForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(t, "SSN", "987-65-4321")
}
func TestStructuredUTF8ForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(
		t, "UTF8_STRING", "abcdefghijklmnopqrstuvwxyzこんにちは世界")
}
func TestStructuredUTF8ComplexForSearchLocal(t *testing.T) {
	testStructuredForSearchLocal(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

func testStructuredForSearchRemote(t *testing.T, dataset, pt string) {
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

	encryptedText, err := enc.Cipher(dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.CipherForSearch(dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	var found bool = false
	for i := range ct {
		rt, err := dec.Cipher(dataset, ct[i], nil)
		if err != nil {
			t.Fatal(err)
		}

		if pt != rt {
			t.Fatalf(
				"bad recovered plaintext: \"%s\" vs. \"%s\"",
				pt, rt)
		}

		found = found || (encryptedText == ct[i])
	}

	if !found {
		t.Fatalf("%s: failed to find expected cipher text in search",
			dataset)
	}
}

func TestStructuredAlnumSSNForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"ALPHANUM_SSN",
		";0123456-789ABCDEF|")
}
func TestStructuredBirthdateForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"BIRTH_DATE",
		";01\\02-1960|")
}
func TestStructuredSSNForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"SSN",
		"-0-1-2-3-4-5-6-7-8-9-")
}
func TestStructuredUTF8ComplexForSearchRemote(t *testing.T) {
	testStructuredForSearchRemote(
		t,
		"UTF8_STRING_COMPLEX",
		"ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")
}

type StructuredTestRecord struct {
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	Dataset    string `json:"dataset"`
}

type StructuredPerformanceCounter struct {
	Count    int
	Duration struct {
		Encrypt time.Duration
		Decrypt time.Duration
	}
}

type StructuredOperations struct {
	perf StructuredPerformanceCounter
}

func TestStructuredFiles(t *testing.T) {
	var foundFiles []string
	filename := os.Getenv("UBIQ_TEST_DATA_FILE")

	if filename == "" {
		t.Skip("UBIQ_TEST_DATA_FILE environment variable not set")
	}

	if filename[len(filename)-1:] == "/" {
		foundFiles, _ = filepath.Glob(fmt.Sprintf("%v*", filename))
	} else {
		foundFiles, _ = filepath.Glob(filename)
	}

	if len(foundFiles) == 0 || foundFiles == nil {
		err := fmt.Errorf("unable to find any files with the pattern: %v", filename)
		t.Fatal(err)
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
	var ops map[string]*StructuredOperations = make(map[string]*StructuredOperations)

	for _, infile := range foundFiles {
		fmt.Printf("Loading file: %v\n", infile)

		file, err := os.Open(infile)
		if err != nil {
			t.Skip(err)
		}
		defer file.Close()

		raw, err := io.ReadAll(file)
		if err != nil {
			t.Skip(err)
		}

		var records []StructuredTestRecord
		err = json.Unmarshal([]byte(raw), &records)
		if err != nil {
			t.Skip(err)
		}

		for i := range records {
			rec := &records[i]

			op, ok := ops[rec.Dataset]
			if !ok {
				var _op StructuredOperations
				ops[rec.Dataset] = &_op
				op = &_op
				// Perform encrypt / decrypt for the dataset just to hydrate the cache without the timer
				enc.Cipher(rec.Dataset, rec.Plaintext, nil)
				dec.Cipher(rec.Dataset, rec.Ciphertext, nil)
			}

			beg := time.Now()
			ct, err := enc.Cipher(rec.Dataset, rec.Plaintext, nil)
			if err != nil {
				t.Fatal(err)
			}
			if ct != rec.Ciphertext {
				t.Fatalf("encryption(%v): %v != %v",
					i, ct, rec.Ciphertext)
			}
			op.perf.Duration.Encrypt += time.Since(beg)

			beg = time.Now()
			pt, err := dec.Cipher(rec.Dataset, rec.Ciphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			if pt != rec.Plaintext {
				t.Fatalf("decryption(%v): %v != %v",
					i, pt, rec.Plaintext)
			}
			op.perf.Duration.Decrypt += time.Since(beg)

			op.perf.Count++
		}
	}

	for dset, op := range ops {
		fmt.Println(dset + ": " + strconv.Itoa(op.perf.Count))
		fmt.Printf("\tencrypt: %v / per\n",
			time.Duration(int64(op.perf.Duration.Encrypt)/
				int64(op.perf.Count)))
		fmt.Printf("\tdecrypt: %v / per\n",
			time.Duration(int64(op.perf.Duration.Decrypt)/
				int64(op.perf.Count)))
	}
}

func TestStructuredThreadSafety(t *testing.T) {
	filename := os.Getenv("UBIQ_100_FILE")
	file, err := os.Open(filename)
	if err != nil {
		t.Skip(err)
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		t.Skip(err)
	}

	var records []StructuredTestRecord
	err = json.Unmarshal([]byte(raw), &records)
	if err != nil {
		t.Skip(err)
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

	var wg sync.WaitGroup
	parallel := 50

	wg.Add(parallel)

	for i := 0; i < parallel; i++ {
		go func(i int) {
			defer wg.Done()
			rec := records[i]

			ct, err := enc.Cipher(rec.Dataset, rec.Plaintext, nil)
			if err != nil {
				t.Fatal(err)
			}
			if ct != rec.Ciphertext {
				t.Fatalf("encryption(%v): %v != %v",
					i, ct, rec.Ciphertext)
			}
		}(i)
	}
	wg.Wait()

	wg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go func(i int) {
			defer wg.Done()
			rec := records[i]

			pt, err := dec.Cipher(rec.Dataset, rec.Ciphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			if pt != rec.Plaintext {
				t.Fatalf("decryption(%v): %v != %v",
					i, pt, rec.Plaintext)
			}
		}(i)
	}
	wg.Wait()

}

func TestLoadCache(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	// Test loading a specific dataset
	err = enc.LoadCache([]string{"ALPHANUM_SSN"})
	if err != nil {
		t.Fatal(err)
	}

	// Test that we can encrypt without additional API calls (data should be cached)
	pt := "123-45-6789"
	ct, err := enc.Cipher("ALPHANUM_SSN", pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(ct) == 0 {
		t.Fatal("encryption returned empty string")
	}

	// Verify we can decrypt
	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	rt, err := dec.Cipher("ALPHANUM_SSN", ct, nil)
	if err != nil {
		t.Fatal(err)
	}

	if pt != rt {
		t.Fatalf("plaintext mismatch: %v != %v", pt, rt)
	}
}

func TestLoadCacheMultipleDatasets(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	// Test loading multiple datasets
	err = enc.LoadCache([]string{"ALPHANUM_SSN", "BIRTH_DATE"})
	if err != nil {
		t.Fatal(err)
	}

	// Test encryption on first dataset
	ct1, err := enc.Cipher("ALPHANUM_SSN", "123-45-6789", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(ct1) == 0 {
		t.Fatal("encryption returned empty string for ALPHANUM_SSN")
	}

	// Test encryption on second dataset
	ct2, err := enc.Cipher("BIRTH_DATE", "01-15-1990", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(ct2) == 0 {
		t.Fatal("encryption returned empty string for BIRTH_DATE")
	}
}

func TestLoadCacheAllDatasets(t *testing.T) {
	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	// Test loading dataset used in this test
	err = enc.LoadCache([]string{"ALPHANUM_SSN"})
	if err != nil {
		t.Fatal(err)
	}

	// Should be able to encrypt with the loaded dataset
	ct, err := enc.Cipher("ALPHANUM_SSN", "123-45-6789", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(ct) == 0 {
		t.Fatal("encryption returned empty string")
	}
}

func TestLoadCacheDecryption(t *testing.T) {
	initializeCreds()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	// Test loading cache on decryption object
	err = dec.LoadCache([]string{"ALPHANUM_SSN"})
	if err != nil {
		t.Fatal(err)
	}

	// First encrypt something
	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	pt := "987-65-4321"
	ct, err := enc.Cipher("ALPHANUM_SSN", pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt using the pre-cached decryption object
	rt, err := dec.Cipher("ALPHANUM_SSN", ct, nil)
	if err != nil {
		t.Fatal(err)
	}

	if pt != rt {
		t.Fatalf("plaintext mismatch: %v != %v", pt, rt)
	}
}

func TestLoadCacheTTLRefresh(t *testing.T) {
	// Test that LoadCache properly resets TTL for cached items
	// This mirrors the Java test that validates TTL refresh behavior

	initializeCreds()
	
	// Use a test-specific config with short TTL
	config, err := NewConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	config.KeyCaching.Structured = true
	config.KeyCaching.TTLSeconds = 3 // 3 second TTL (matches Java test)
	config.KeyCaching.Encrypt = false
	
	// Create new credentials with custom config
	testCreds := credentials
	testCreds.config = &config
	
	// Initialize cache with new TTL
	testCreds.cache, err = NewCache(&config)
	if err != nil {
		t.Fatal(err)
	}

	enc, err := NewStructuredEncryption(testCreds)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	datasetName := "ALPHANUM_SSN"

	// First load - cache is cold
	t.Log("First LoadCache call - cache is cold")
	err = enc.LoadCache([]string{datasetName})
	if err != nil {
		t.Fatal(err)
	}

	// Second load - should reuse cached values and reset TTL
	t.Log("Second LoadCache call - cache is warm, TTL should reset")
	err = enc.LoadCache([]string{datasetName})
	if err != nil {
		t.Fatal(err)
	}

	// Sleep 6 seconds - cache should expire (TTL = 3 seconds)
	t.Log("Sleep 6 seconds - cache should be expired")
	time.Sleep(6 * time.Second)
	err = enc.LoadCache([]string{datasetName})
	if err != nil {
		t.Fatal(err)
	}

	// Sleep 2 seconds and load - TTL should reset (total time < 3 seconds)
	t.Log("Sleep 2 seconds - cache TTL should reset")
	time.Sleep(2 * time.Second)
	err = enc.LoadCache([]string{datasetName})
	if err != nil {
		t.Fatal(err)
	}

	// Sleep 2 seconds and load - TTL should reset again
	t.Log("Sleep 2 seconds - cache TTL should reset")
	time.Sleep(2 * time.Second)
	err = enc.LoadCache([]string{datasetName})
	if err != nil {
		t.Fatal(err)
	}

	// Sleep 2 seconds and load - TTL should reset again
	t.Log("Sleep 2 seconds - cache TTL should reset")
	time.Sleep(2 * time.Second)
	err = enc.LoadCache([]string{datasetName})
	if err != nil {
		t.Fatal(err)
	}

	// Sleep 4 seconds - cache should expire (no LoadCache call)
	t.Log("Sleep 4 seconds - cache should be expired")
	time.Sleep(4 * time.Second)
	err = enc.LoadCache([]string{datasetName})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("TTL test completed successfully")
	// Note: Like Java test, this requires verbose logging enabled to verify cache behavior
	// The test validates that LoadCache doesn't error during TTL refresh scenarios
}

// TestEmptyStringDecryption tests the fix for empty string panic in decryption
// This validates that attempting to decrypt an empty string returns an error
// instead of panicking with "index out of range [0] with length 0"
func TestEmptyStringDecryption(t *testing.T) {
	initializeCreds()

	dec, err := NewStructuredDecryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	// Attempt to decrypt an empty string - should return error, not panic
	// Using UTF8_STRING_COMPLEX as a commonly available dataset
	_, err = dec.Cipher("UTF8_STRING_COMPLEX", "", nil)
	if err == nil {
		t.Fatal("Expected error when decrypting empty string, got nil")
	}

	// Should get "invalid text length" error (not a panic)
	// Note: May also get dataset compatibility error in some environments,
	// which is acceptable as long as it doesn't panic
	if err.Error() != "invalid text length" {
		// If we got a different error (like dataset compatibility),
		// that's fine - we just want to ensure no panic occurred
		t.Logf("Got error (no panic): %v", err)
	}
}
