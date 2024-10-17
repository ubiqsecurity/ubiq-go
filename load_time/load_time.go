package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/ubiqsecurity/ubiq-go"
)

const (
	exitSuccess int = 0
	exitFailure
)

// parameters is used to convey command line
// options to the main function
type parameters struct {
	maxEncrypt, maxDecrypt, avgEncrypt, avgDecrypt int
	infile_base, credfile, profile                 string
	infiles                                        []string
}

type testCase struct {
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	Dataset    string `json:"dataset"`
}

type timerdata struct {
	ElapsedTimes []int
	Count        int
}

type StructuredStatistics struct {
	Min      time.Duration
	Max      time.Duration
	Duration time.Duration
}
type StructuredPerformanceCounter struct {
	Count   int
	Encrypt StructuredStatistics
	Decrypt StructuredStatistics
}

type StructuredOperations struct {
	enc *ubiq.StructuredEncryption
	dec *ubiq.StructuredDecryption

	perf StructuredPerformanceCounter
}

func usage(args ...string) {
	status := exitSuccess
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n\n", args[0])
		status = exitFailure
	}

	fmt.Fprintf(os.Stderr, "Usage: %s -e|-d|-E|-D NUMBER -i INFILE\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Load test for bulk encrypting/decrypting with the Ubiq service\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  -h, -help               Show this help message and exit\n")
	fmt.Fprintf(os.Stderr, "  -V, -version            Show program's version number and exit\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  -i, -in                 File(s) to use containing cipher and plain text pairs\n")
	fmt.Fprintf(os.Stderr, "                            with datasets. Supports asterisk (*) for wildcard in \n")
	fmt.Fprintf(os.Stderr, "                            path/filename. Directories should end in / \n")
	fmt.Fprintf(os.Stderr, "  -c CREDENTIALS, -creds CREDENTIALS\n")
	fmt.Fprintf(os.Stderr, "                          Set the file name with the API credentials\n")
	fmt.Fprintf(os.Stderr, "                            (default: ~/.ubiq/credentials)\n")
	fmt.Fprintf(os.Stderr, "  -P PROFILE, -profile PROFILE\n")
	fmt.Fprintf(os.Stderr, "                          Identify the profile within the credentials file\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  OPTIONAL: For determining performance limits\n")
	fmt.Fprintf(os.Stderr, "  -e, -avgencrypt         Maximum average time in microseconds for encryption\n")
	fmt.Fprintf(os.Stderr, "  -d, -avgdecrypt         Maximum average time in microseconds for decryption\n")
	fmt.Fprintf(os.Stderr, "  -E, -maxencrypt         Maximum total time in microseconds for encryption\n")
	fmt.Fprintf(os.Stderr, "  -D, -maxdecrypt         Maximum total time in microseconds for decryption\n")
	fmt.Fprintf(os.Stderr, "\n")

	os.Exit(status)
}

func min(a, b time.Duration) time.Duration {
	if a == 0 {
		return b
	}
	if a <= b {
		return a
	}
	return b
}

func max(a, b time.Duration) time.Duration {
	if a == 0 {
		return b
	}
	if a >= b {
		return a
	}
	return b
}

func getopts() (parameters, error) {
	var help, version, debug bool = false, false, false
	var params parameters
	var err error

	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	f.BoolVar(&help, "h", false, "")
	f.BoolVar(&help, "help", false, "")
	f.BoolVar(&version, "V", false, "")
	f.BoolVar(&version, "version", false, "")

	f.BoolVar(&debug, "debug", false, "")

	f.IntVar(&params.maxEncrypt, "E", 0, "")
	f.IntVar(&params.maxEncrypt, "maxencrypt", 0, "")
	f.IntVar(&params.maxDecrypt, "D", 0, "")
	f.IntVar(&params.maxDecrypt, "maxdecrypt", 0, "")
	f.IntVar(&params.avgEncrypt, "e", 0, "")
	f.IntVar(&params.avgEncrypt, "avgencrypt", 0, "")
	f.IntVar(&params.avgDecrypt, "d", 0, "")
	f.IntVar(&params.avgDecrypt, "avgdecrypt", 0, "")

	f.StringVar(&params.infile_base, "i", "", "")
	f.StringVar(&params.infile_base, "in", "", "")
	f.StringVar(&params.credfile, "c", "", "")
	f.StringVar(&params.credfile, "creds", "", "")
	f.StringVar(&params.profile, "P", "", "")
	f.StringVar(&params.profile, "profile", "", "")

	f.Parse(os.Args[1:])

	if help {
		usage()
	}
	if version {
		fmt.Fprintf(os.Stderr, "version %s\n", ubiq.Version)
		os.Exit(exitSuccess)
	}

	var foundFiles []string
	// If last character is `/`, it's a directory. Otherwise assume it's a file.
	if params.infile_base[len(params.infile_base)-1:] == "/" {
		foundFiles, err = filepath.Glob(fmt.Sprintf("%v*", params.infile_base))
	} else {
		foundFiles, err = filepath.Glob(params.infile_base)
	}

	if len(foundFiles) == 0 || foundFiles == nil {
		return params, fmt.Errorf("unable to find any files with the pattern: %v", params.infile_base)
	}
	if err != nil {
		return params, err
	}

	params.infiles = append(params.infiles, foundFiles[:]...)

	if debug {
		fmt.Printf("Found files: \n%v\n", strings.Join(params.infiles, "\n"))
	}

	return params, nil
}

func load_test(creds ubiq.Credentials, params parameters) error {
	count := 0
	var ops map[string]*StructuredOperations = make(map[string]*StructuredOperations)
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	defer enc.Close()
	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		return err
	}
	defer dec.Close()
	for _, infile := range params.infiles {
		fmt.Printf("Loading file: %v\n", infile)
		content, err := os.ReadFile(infile)
		if err != nil {
			if strings.Contains(fmt.Sprintf("%v", err), "is a directory") {
				return fmt.Errorf("%v is a directory. Ensure directory paths end in /", infile)
			}
			return err
		}

		var testCases []testCase
		err = json.Unmarshal(content, &testCases)
		if err != nil {
			return err
		}

		for _, c := range testCases {
			op, ok := ops[c.Dataset]
			if !ok {
				var _op StructuredOperations
				ops[c.Dataset] = &_op
				op = &_op
			}

			startEnc := time.Now()
			ct, err := enc.Cipher(c.Dataset, c.Plaintext, nil)
			enc_elapsed := time.Since(startEnc)
			op.perf.Encrypt.Duration += enc_elapsed
			op.perf.Encrypt.Min = min(op.perf.Encrypt.Min, enc_elapsed)
			op.perf.Encrypt.Max = max(op.perf.Encrypt.Max, enc_elapsed)

			if err != nil {
				return err
			}

			if c.Ciphertext != ct {
				return fmt.Errorf("ciphertext did not match encrypted plaintext '%s' != '%s'", c.Ciphertext, ct)
			}

			startDec := time.Now()
			pt, err := dec.Cipher(c.Dataset, c.Ciphertext, nil)
			dec_elapsed := time.Since(startDec)
			op.perf.Decrypt.Duration += dec_elapsed
			op.perf.Decrypt.Min = min(op.perf.Decrypt.Min, dec_elapsed)
			op.perf.Decrypt.Max = max(op.perf.Decrypt.Max, dec_elapsed)

			if err != nil {
				return err
			}

			if c.Plaintext != pt {
				return fmt.Errorf("plaintext did not match decrypted ciphertext '%s' != '%s'", c.Plaintext, pt)
			}

			op.perf.Count++
			count++
		}
	}

	encAvg, encTotal, decAvg, decTotal := printOutput(ops)

	var res []bool
	res = append(res, evaluateThreshold(params.avgEncrypt, encAvg, "average encrypt"))
	res = append(res, evaluateThreshold(params.avgDecrypt, decAvg, "average encrypt"))
	res = append(res, evaluateThreshold(params.maxEncrypt, encTotal, "total encrypt"))
	res = append(res, evaluateThreshold(params.maxDecrypt, decTotal, "total encrypt"))

	acc := true
	for _, v := range res {
		acc = acc && v
	}

	if !acc {
		return fmt.Errorf("one or more thresholds failed")
	}
	return nil
}

func printOutput(datasetTimes map[string]*StructuredOperations) (encAvg, encTotal, decAvg, decTotal time.Duration) {
	count := 0
	encOutput := make([]string, len(datasetTimes))
	decOutput := make([]string, len(datasetTimes))
	i := 0
	for datasetName, ops := range datasetTimes {
		encOutput[i] = fmt.Sprintf("    Dataset: %v, Count: %v Average: %v, Total %v, Min: %v, Max: %v\n", datasetName, ops.perf.Count, time.Duration(float64(ops.perf.Encrypt.Duration)/float64(ops.perf.Count)), ops.perf.Encrypt.Duration, ops.perf.Encrypt.Min, ops.perf.Encrypt.Max)
		decOutput[i] = fmt.Sprintf("    Dataset: %v, Count: %v Average: %v, Total %v, Min: %v, Max: %v\n", datasetName, ops.perf.Count, time.Duration(float64(ops.perf.Decrypt.Duration)/float64(ops.perf.Count)), ops.perf.Decrypt.Duration, ops.perf.Decrypt.Min, ops.perf.Decrypt.Max)
		encTotal += ops.perf.Encrypt.Duration
		decTotal += ops.perf.Decrypt.Duration
		count += ops.perf.Count
		i++
	}
	encAvg = time.Duration(float64(encTotal) / float64(count))
	decAvg = time.Duration(float64(decTotal) / float64(count))
	fmt.Printf("Encrypt records count: %v.\n", count)
	for _, statement := range encOutput {
		fmt.Printf("%v", statement)
	}
	fmt.Printf("        ENC Total: Average: %v, Total: %v\n", encAvg, encTotal)

	fmt.Printf("Decrypt records count: %v.\n", count)
	for _, statement := range decOutput {
		fmt.Printf("%v", statement)
	}
	fmt.Printf("        DEC Total: Average: %v, Total: %v\n", decAvg, decTotal)

	return encAvg, encTotal, decAvg, decTotal
}

func evaluateThreshold(threshold int, reality time.Duration, label string) bool {
	timeThreshold := time.Duration(threshold) * time.Microsecond
	if threshold == 0 {
		fmt.Printf("NOTE: No maximum allowed %v threshold supplied\n", label)
		return true
	}

	if reality < timeThreshold {
		fmt.Printf("PASSED: Maximum allowed %v threshold of %v microseconds\n", label, threshold)
		return true
	} else {
		fmt.Printf("FAILED: Exceeded maximum allowed %v threshold of %v microseconds\n", label, threshold)
		return false
	}
}

func _main(params parameters, err error) error {
	if err != nil {
		return err
	}
	// new credentials
	credentials, err :=
		ubiq.NewCredentials(
			params.credfile, params.profile)
	if err != nil {
		return err
	}

	err = load_test(credentials, params)

	return err
}

func main() {
	// os.Exit immediately exits the program without running
	// any deferred functions. therefore, the main functionality
	// is located in the _main function, allowing deferred
	// functions to run prior to returning. os.Exit is then
	// called from this function in response to any errors
	err := _main(getopts())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encountered: %v\n", err)
		os.Exit(exitFailure)
	}
}
