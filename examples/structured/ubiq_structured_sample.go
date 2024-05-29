package main

import (
	"flag"
	"fmt"
	"os"

	"gitlab.com/ubiqsecurity/ubiq-go"
)

const (
	exitSuccess int = 0
	exitFailure
)

const maxSimpleSize = 50 * 1024 * 1024

type mode int

const (
	modeEncrypt mode = iota
	modeDecrypt
)

type method int

const (
	methodSimple method = iota
	methodPiecewise
)

// parameters is used to convey command line
// options to the main function
type parameters struct {
	mode                                             mode
	method                                           method
	encrypt, decrypt, credfile, profile, datasetName string
}

func usage(args ...string) {
	status := exitSuccess
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n\n", args[0])
		status = exitFailure
	}

	fmt.Fprintf(os.Stderr, "Usage: %s -e|-d -s|-p -i INFILE -o OUTFILE\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Encrypt or decrypt files using the Ubiq service\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  -h, -help               Show this help message and exit\n")
	fmt.Fprintf(os.Stderr, "  -V, -version            Show program's version number and exit\n")
	fmt.Fprintf(os.Stderr, "  -e, -encrypttext        Set the field text value to encrypt and will\n")
	fmt.Fprintf(os.Stderr, "                            return the encrypted cipher text.\n")
	fmt.Fprintf(os.Stderr, "  -d, -decrypttext        Set the cipher text value to decrypt and will\n")
	fmt.Fprintf(os.Stderr, "                            return the decrypted text.\n")
	fmt.Fprintf(os.Stderr, "  -n, -datasetName        Set the name of the dataset, for example SSN.\n")
	fmt.Fprintf(os.Stderr, "  -c CREDENTIALS, -creds CREDENTIALS\n")
	fmt.Fprintf(os.Stderr, "                          Set the file name with the API credentials\n")
	fmt.Fprintf(os.Stderr, "                            (default: ~/.ubiq/credentials)\n")
	fmt.Fprintf(os.Stderr, "  -P PROFILE, -profile PROFILE\n")
	fmt.Fprintf(os.Stderr, "                          Identify the profile within the credentials file\n")

	os.Exit(status)
}

func getopts() parameters {
	var help, version bool = false, false
	var params parameters

	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	f.BoolVar(&help, "h", false, "")
	f.BoolVar(&help, "help", false, "")
	f.BoolVar(&version, "V", false, "")
	f.BoolVar(&version, "version", false, "")

	f.StringVar(&params.encrypt, "e", "", "")
	f.StringVar(&params.encrypt, "encrypttext", "", "")
	f.StringVar(&params.decrypt, "d", "", "")
	f.StringVar(&params.decrypt, "decrypttext", "", "")
	f.StringVar(&params.datasetName, "n", "", "")
	f.StringVar(&params.datasetName, "datasetName", "", "")

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

	if len(params.encrypt) > 0 && len(params.decrypt) > 0 {
		usage("please specify one of encrypt or decrypt operations")
	} else if len(params.encrypt) > 0 {
		params.mode = modeEncrypt
	} else /* decrypt */ {
		params.mode = modeDecrypt
	}

	return params
}

func simpleEncrypt(creds ubiq.Credentials, datasetName string, plainText string) error {
	var cipherText, err = ubiq.FPEncrypt(creds, datasetName, plainText, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ENCRYPTED cipher= %s \n", cipherText)
	return err
}

func simpleDecrypt(creds ubiq.Credentials, datasetName string, cipherText string) error {
	var plainText, err = ubiq.FPDecrypt(creds, datasetName, cipherText, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "DECRYPTED plainText= %s \n", plainText)
	return err
}

func _main(params parameters) error {
	// new credentials
	credentials, err :=
		ubiq.NewCredentials(
			params.credfile, params.profile)
	if err != nil {
		return err
	}

	// encrypt or decrypt using the specified method
	if params.mode == modeEncrypt {
		err = simpleEncrypt(credentials, params.datasetName, params.encrypt)
	} else /* decrypt */ {
		err = simpleDecrypt(credentials, params.datasetName, params.decrypt)
	}
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
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(exitFailure)
	}
}
