package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	encDatasets := make(map[string]timerdata)
	decDatasets := make(map[string]timerdata)

	count := 0
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
			datasetName := c.Dataset
			_, ok := encDatasets[datasetName]
			if !ok {
				ubiq.FPEncrypt(creds, datasetName, c.Plaintext, nil)
				ubiq.FPDecrypt(creds, datasetName, c.Ciphertext, nil)
				encDatasets[datasetName] = timerdata{ElapsedTimes: make([]int, 0), Count: 0}
				decDatasets[datasetName] = timerdata{ElapsedTimes: make([]int, 0), Count: 0}
			}

			startEnc := time.Now()
			ct, err := ubiq.FPEncrypt(creds, datasetName, c.Plaintext, nil)
			endEnc := time.Now()
			encElapsed := endEnc.Sub(startEnc)

			if err != nil {
				return err
			}

			if c.Ciphertext != ct {
				return fmt.Errorf("ciphertext did not match encrypted plaintext '%s' != '%s'", c.Ciphertext, ct)
			}

			if encSet, ok := encDatasets[datasetName]; ok {
				encSet.ElapsedTimes = append(encSet.ElapsedTimes, int(encElapsed)/1000)
				encSet.Count += 1
				encDatasets[datasetName] = encSet
			}

			startDec := time.Now()
			pt, err := ubiq.FPDecrypt(creds, datasetName, c.Ciphertext, nil)
			endDec := time.Now()
			decElapsed := endDec.Sub(startDec)

			if err != nil {
				return err
			}

			if c.Plaintext != pt {
				return fmt.Errorf("plaintext did not match decrypted ciphertext '%s' != '%s'", c.Plaintext, pt)
			}

			if decSet, ok := decDatasets[datasetName]; ok {
				decSet.ElapsedTimes = append(decSet.ElapsedTimes, int(decElapsed)/1000)
				decSet.Count += 1
				decDatasets[datasetName] = decSet
			}

			count += 1
		}
	}

	fmt.Printf("Encrypt records count: %v. Times in microseconds\n", count)
	encAvg, encTotal := printOutput(encDatasets)
	fmt.Printf("Decrypt records count: %v. Times in microseconds\n", count)
	decAvg, decTotal := printOutput(decDatasets)

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

func printOutput(datasetTimes map[string]timerdata) (average int, total int) {
	total = 0
	count := 0
	for datasetName, timing := range datasetTimes {
		totalTime := 0
		for _, v := range timing.ElapsedTimes {
			totalTime += v
		}

		slices.Sort(timing.ElapsedTimes)
		minTime := timing.ElapsedTimes[0]
		maxTime := timing.ElapsedTimes[len(timing.ElapsedTimes)-1]
		fmt.Printf("    Dataset: %v, Count: %v Average: %v, Total %v, Min: %v, Max: %v\n", datasetName, timing.Count, int(float64(totalTime)/float64(timing.Count)), totalTime, minTime, maxTime)
		total += totalTime
		count += timing.Count
	}
	average = int(float64(total) / float64(count))
	fmt.Printf("        Total: Average: %v, Total: %v\n", average, total)

	return average, total
}

func evaluateThreshold(threshold int, reality int, label string) bool {
	if threshold == 0 {
		fmt.Printf("NOTE: No maximum allowed %v threshold supplied\n", label)
		return true
	}

	if reality < threshold {
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
