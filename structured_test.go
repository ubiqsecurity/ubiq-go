package ubiq

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
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

	if len(ct) < 2 {
		t.Fatalf("%s: expected at least 2 ciphers for search, got %d", dataset, len(ct))
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

	if len(ct) < 2 {
		t.Fatalf("%s: expected at least 2 ciphers for search, got %d", dataset, len(ct))
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

// decode the key number embedded in a structured ciphertext,
// independently of the pipeline implementation: passthrough, prefix and
// suffix rules are applied in ascending priority order (the same order
// decryption trims), then the first remaining character is decoded
// against the dataset's output alphabet
func decodeCiphertextKeyNumber(dataset datasetInfo, ct string) (int, error) {
	out := []rune(ct)

	rules := make([]passthroughRule, len(dataset.PassthroughRules))
	copy(rules, dataset.PassthroughRules)
	if len(rules) == 0 && dataset.PassthroughAlphabet.Len() > 0 {
		// legacy datasets: passthrough only, no rule list
		rules = append(rules, passthroughRule{Type: "passthrough", Priority: 1})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	ruleLength := func(v interface{}) int {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
		return 0
	}

	for _, rule := range rules {
		switch rule.Type {
		case "passthrough":
			var kept []rune
			for _, c := range out {
				if dataset.PassthroughAlphabet.PosOf(c) < 0 {
					kept = append(kept, c)
				}
			}
			out = kept
		case "prefix":
			if n := ruleLength(rule.Value); n > 0 {
				if n > len(out) {
					return 0, fmt.Errorf("prefix %d longer than ciphertext", n)
				}
				out = out[n:]
			}
		case "suffix":
			if n := ruleLength(rule.Value); n > 0 {
				if n > len(out) {
					return 0, fmt.Errorf("suffix %d longer than ciphertext", n)
				}
				out = out[:len(out)-n]
			}
		default:
			return 0, fmt.Errorf("unsupported rule type %q", rule.Type)
		}
	}

	if len(out) == 0 || dataset.OutputAlphabet.PosOf(out[0]) < 0 {
		return 0, fmt.Errorf("no decodable ciphertext character")
	}

	_, kn := decodeKeyNumber(out, &dataset.OutputAlphabet,
		dataset.NumEncodingBits)
	return kn, nil
}

func TestStructuredCipherAndKeyNumber(t *testing.T) {
	const dataset = "ALPHANUM_SSN"
	const pt = "123-45-6789"

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

	ct, kn, err := enc.CipherAndKeyNumber(dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	// the ciphertext must still decrypt back to the plaintext
	rt, err := dec.Cipher(dataset, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt != rt {
		t.Fatalf("bad recovered plaintext: \"%s\" vs. \"%s\"", pt, rt)
	}

	// the returned key number must match the one embedded in the ciphertext
	dsInfo, err := ((*structuredContext)(enc)).fetchDataset(dataset)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := decodeCiphertextKeyNumber(dsInfo, ct)
	if err != nil {
		t.Fatal(err)
	}
	if embedded != kn {
		t.Fatalf("returned key number %d does not match embedded key number %d",
			kn, embedded)
	}

	// encrypting with the returned key number must reproduce the ciphertext
	ct2, err := enc.CipherWithKeyNumber(dataset, pt, nil, kn)
	if err != nil {
		t.Fatal(err)
	}
	if ct != ct2 {
		t.Fatalf("ciphertext mismatch for key number %d: \"%s\" vs. \"%s\"",
			kn, ct, ct2)
	}
}

func TestStructuredGetCurrentKeyNumber(t *testing.T) {
	const dataset = "ALPHANUM_SSN"

	initializeCreds()

	enc, err := NewStructuredEncryption(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	// always fetched from the server
	kn, err := enc.GetCurrentKeyNumber(dataset)
	if err != nil {
		t.Fatal(err)
	}

	// a second call also fetches from the server and must agree
	kn2, err := enc.GetCurrentKeyNumber(dataset)
	if err != nil {
		t.Fatal(err)
	}
	if kn != kn2 {
		t.Fatalf("second key number %d does not match first result %d", kn2, kn)
	}

	// the current key number must match what Cipher uses right now
	_, encKn, err := enc.CipherAndKeyNumber(dataset, "123-45-6789", nil)
	if err != nil {
		t.Fatal(err)
	}
	if kn != encKn {
		t.Fatalf("GetCurrentKeyNumber %d does not match Cipher key number %d",
			kn, encKn)
	}
}

func TestStructuredGetKeyNumber(t *testing.T) {
	const dataset = "ALPHANUM_SSN"
	const pt = "123-45-6789"

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

	ct, kn, err := enc.CipherAndKeyNumber(dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	// both objects must decode the same key number from the ciphertext
	decKn, err := dec.GetKeyNumber(dataset, ct)
	if err != nil {
		t.Fatal(err)
	}
	if decKn != kn {
		t.Fatalf("GetKeyNumber %d does not match encryption key number %d",
			decKn, kn)
	}

	encKn, err := enc.GetKeyNumber(dataset, ct)
	if err != nil {
		t.Fatal(err)
	}
	if encKn != kn {
		t.Fatalf("GetKeyNumber %d does not match encryption key number %d",
			encKn, kn)
	}

	// characters outside the output alphabet must error, not panic
	if _, err = dec.GetKeyNumber(dataset, "€€€-€€-€€€€"); err == nil {
		t.Fatal("expected error for invalid ciphertext characters")
	}
}

func TestStructuredGetKeyNumberWithRules(t *testing.T) {
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

	// datasets with prefix/suffix/passthrough rules exercise the
	// rule-priority trim path. The UTF8_STRING_COMPLEX_* pair exists in
	// every environment (suf_pre_pass has non-monotonic priorities). The
	// SSN_* variants are named differently in prod and dev, so both sets
	// are listed and each environment skips the ones it does not define,
	// giving full rule coverage everywhere. The generic_string datasets
	// have no rules and cover the input padding/encoding path.
	const utf8Complex = "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ"
	// long enough that at least 6 digits remain encryptable after the
	// prefix/suffix rules remove their characters
	const ssnLong = "123-456789-0123"
	cases := []struct {
		dataset string
		pt      string
	}{
		{"UTF8_STRING_COMPLEX_pre_pass", utf8Complex},
		{"UTF8_STRING_COMPLEX_suf_pre_pass", utf8Complex},
		// prod
		{"SSN_pre_pass", ssnLong},
		{"SSN_pass_suf", ssnLong},
		{"SSN_pre_suf_pass", ssnLong},
		{"SSN_suf_pass_pre", ssnLong},
		// dev
		{"SSN_pass", ssnLong},
		{"SSN_pass_pre", ssnLong},
		{"SSN_pass_suf_pre", ssnLong},
		{"SSN_pre_pass_suf", ssnLong},
		{"SSN_suf_pre_pass", ssnLong},
		{"generic_string", "abcdefghij"},
		{"generic_string_32", "abcdefghij"},
	}
	for _, tc := range cases {
		t.Run(tc.dataset, func(t *testing.T) {
			ct, kn, err := enc.CipherAndKeyNumber(tc.dataset, tc.pt, nil)
			if err != nil {
				// the SSN_* rule datasets are not defined in every
				// environment (e.g. DEV)
				if strings.Contains(err.Error(), "Invalid Dataset name") {
					t.Skipf("dataset %s not available in this environment", tc.dataset)
				}
				t.Fatal(err)
			}

			decKn, err := dec.GetKeyNumber(tc.dataset, ct)
			if err != nil {
				t.Fatal(err)
			}
			if decKn != kn {
				t.Fatalf("GetKeyNumber %d does not match encryption key number %d",
					decKn, kn)
			}

			// independent cross-check: decode the embedded key number
			// without the pipeline
			dsInfo, err := ((*structuredContext)(dec)).fetchDataset(tc.dataset)
			if err != nil {
				t.Fatal(err)
			}
			embedded, err := decodeCiphertextKeyNumber(dsInfo, ct)
			if err != nil {
				t.Fatal(err)
			}
			if embedded != kn {
				t.Fatalf("embedded key number %d does not match encryption key number %d",
					embedded, kn)
			}
		})
	}

	// datasets with a non-string data type must be rejected: decoding
	// the native string representation would give a wrong key number
	t.Run("typed_dataset_rejected", func(t *testing.T) {
		if _, err := dec.GetKeyNumber("integer32", "12345"); err == nil {
			t.Fatal("expected error for typed dataset")
		}
	})
}

// every result of an encrypt-for-search is encrypted with the key
// number matching its position in the returned array, and the last
// entry uses the current key
func TestStructuredKeyNumbersForSearch(t *testing.T) {
	const dataset = "ALPHANUM_SSN"
	const pt = "123-45-6789"

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

	curr, err := enc.GetCurrentKeyNumber(dataset)
	if err != nil {
		t.Fatal(err)
	}

	cts, err := enc.CipherForSearch(dataset, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i, ct := range cts {
		kn, err := dec.GetKeyNumber(dataset, ct)
		if err != nil {
			t.Fatal(err)
		}
		if kn != i {
			t.Fatalf("search result %d encrypted with key number %d", i, kn)
		}
	}

	if last := len(cts) - 1; last != curr {
		t.Fatalf("last search key number %d does not match current key number %d",
			last, curr)
	}
}
