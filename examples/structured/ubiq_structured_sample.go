package main

import (
	"flag"
	"fmt"
	"os"

	"gitlab.com/ubiqsecurity/ubiq-go/v2"
)

const (
	exitSuccess int = 0
	exitFailure
)

type mode int

const (
	modeEncrypt mode = iota
	modeDecrypt
)

// parameters is used to convey command line
// options to the main function
type parameters struct {
	search                                           bool
	mode                                             mode
	encrypt, decrypt, credfile, profile, datasetName string
}

func usage(args ...string) {
	status := exitSuccess
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n\n", args[0])
		status = exitFailure
	}

	fmt.Fprintf(os.Stderr, "Usage: %s \n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Encrypt or decrypt text using the Ubiq service\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
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
	fmt.Fprintf(os.Stderr, "  -s, -search            Perform an Encrypt For Search.  Only compatible with the -e option\n")

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

	f.BoolVar(&params.search, "s", false, "")
	f.BoolVar(&params.search, "search", false, "")

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

	if (params.search && modeDecrypt == params.mode) {
		usage("Encrypt For Search can only be used with encryption")
	}


	return params
}

func encrypt(creds ubiq.Credentials, datasetName string, plainText string) error {
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	cipherText, err := enc.Cipher(datasetName, plainText, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ENCRYPTED cipher= %s \n", cipherText)
	return err
}

func encryptForSearch(creds ubiq.Credentials, datasetName string, plainText string) error {
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	cipherText, err := enc.CipherForSearch(datasetName, plainText, nil)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "EncryptForSearch results:\n")
	for _, value := range cipherText {
		fmt.Fprintf(os.Stdout, "\t %s\n", value)
	}
	return err
}

func decrypt(creds ubiq.Credentials, datasetName string, cipherText string) error {
	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		return err
	}
	plainText, err := dec.Cipher(datasetName, cipherText, nil)
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
		if (params.search) {
			err = encryptForSearch(credentials, params.datasetName, params.encrypt)
		} else {
			err = encrypt(credentials, params.datasetName, params.encrypt)
		}
	} else /* decrypt */ {
		err = decrypt(credentials, params.datasetName, params.decrypt)
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
