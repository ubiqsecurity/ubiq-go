package main

import (
	"flag"
	"fmt"

	"io"
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
	methodChunking
)

// parameters is used to convey command line
// options to the main function
type parameters struct {
	mode                               mode
	method                             method
	infile, outfile, credfile, profile string
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
	fmt.Fprintf(os.Stderr, "  -e, -encrypt            Encrypt the contents of the input file and write\n")
	fmt.Fprintf(os.Stderr, "                            the results to the output file\n")
	fmt.Fprintf(os.Stderr, "  -d, -decrypt            Decrypt the contents of the input file and write\n")
	fmt.Fprintf(os.Stderr, "                            the results to the output file\n")
	fmt.Fprintf(os.Stderr, "  -s, -simple             Use the simple encryption / decryption interfaces\n")
	fmt.Fprintf(os.Stderr, "  -p, -chunking           Use the encryption / decryption interfaces to handle\n")
	fmt.Fprintf(os.Stderr, "                            large data elements where data is loadedin chunks\n")
	fmt.Fprintf(os.Stderr, "  -i INFILE, -in INFILE   Set input file name\n")
	fmt.Fprintf(os.Stderr, "  -o OUTFILE, -out OUTFILE\n")
	fmt.Fprintf(os.Stderr, "                          Set output file name\n")
	fmt.Fprintf(os.Stderr, "  -c CREDENTIALS, -creds CREDENTIALS\n")
	fmt.Fprintf(os.Stderr, "                          Set the file name with the API credentials\n")
	fmt.Fprintf(os.Stderr, "                            (default: ~/.ubiq/credentials)\n")
	fmt.Fprintf(os.Stderr, "  -P PROFILE, -profile PROFILE\n")
	fmt.Fprintf(os.Stderr, "                          Identify the profile within the credentials file\n")

	os.Exit(status)
}

func getopts() parameters {
	var help, version bool = false, false
	var encrypt, decrypt bool = false, false
	var simple, chunking bool = false, false
	var params parameters

	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	f.BoolVar(&help, "h", false, "")
	f.BoolVar(&help, "help", false, "")
	f.BoolVar(&version, "V", false, "")
	f.BoolVar(&version, "version", false, "")

	f.BoolVar(&encrypt, "e", false, "")
	f.BoolVar(&encrypt, "encrypt", false, "")
	f.BoolVar(&decrypt, "d", false, "")
	f.BoolVar(&decrypt, "decrypt", false, "")

	f.BoolVar(&simple, "s", false, "")
	f.BoolVar(&simple, "simple", false, "")
	f.BoolVar(&chunking, "p", false, "")
	f.BoolVar(&chunking, "chunking", false, "")

	f.StringVar(&params.infile, "i", "", "")
	f.StringVar(&params.infile, "in", "", "")
	f.StringVar(&params.outfile, "o", "", "")
	f.StringVar(&params.outfile, "out", "", "")

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

	if encrypt == decrypt {
		usage("please specify one of encrypt or decrypt operations")
	} else if encrypt {
		params.mode = modeEncrypt
	} else /* decrypt */ {
		params.mode = modeDecrypt
	}

	if simple == chunking {
		usage("please specify one of simple or chunking methods")
	} else if simple {
		params.method = methodSimple
	} else /* chunking */ {
		params.method = methodChunking
	}

	if len(params.infile) == 0 {
		usage("input file not specified")
	}

	if len(params.outfile) == 0 {
		usage("output file not specified")
	}

	return params
}

func simpleEncrypt(c ubiq.Credentials, ifp, ofp *os.File, size int64) error {
	pt := make([]byte, size)

	// read the whole file
	_, err := ifp.Read(pt)
	if err == nil {
		var ct []byte

		// encrypt the whole file
		ct, err = ubiq.Encrypt(c, pt)
		if err == nil {
			// write the whole file
			_, err = ofp.Write(ct)
		}
	}

	return err
}

func chunkingEncrypt(c ubiq.Credentials, ifp, ofp *os.File) error {
	var pt, ct []byte = make([]byte, 128*1024), []byte{}

	// new encryption object
	enc, err := ubiq.NewEncryption(c, 1)
	if err != nil {
		return err
	}
	defer enc.Close()

	// start the new encryption and write out
	// any cipher text produced
	ct, err = enc.Begin()
	if err != nil {
		return err
	}
	_, err = ofp.Write(ct)

	// read chunks of data and encrypt them,
	// writing the results to the output file
	for err == nil {
		var n int

		n, err = ifp.Read(pt)
		if err == nil {
			ct, err = enc.Update(pt[:n])
			if err == nil {
				_, err = ofp.Write(ct)
			}
		} else if err == io.EOF {
			err = nil
			break
		}
	}

	// finalize the encryption, writing any
	// remaining cipher text to the output file
	if err == nil {
		ct, err = enc.End()
		if err == nil {
			_, err = ofp.Write(ct)
		}
	}

	return err
}

func simpleDecrypt(c ubiq.Credentials, ifp, ofp *os.File, size int64) error {
	ct := make([]byte, size)

	// read the whole file
	_, err := ifp.Read(ct)
	if err == nil {
		var pt []byte

		// decrypt the whole file
		pt, err = ubiq.Decrypt(c, ct)
		if err == nil {
			// write the whole file
			_, err = ofp.Write(pt)
		}
	}

	return err
}

func chunkingDecrypt(c ubiq.Credentials, ifp, ofp *os.File) error {
	var ct, pt []byte = make([]byte, 128*1024), []byte{}

	// new decryption object
	dec, err := ubiq.NewDecryption(c)
	if err != nil {
		return err
	}
	defer dec.Close()

	// start the new decryption and write out
	// any plain text produced
	pt, err = dec.Begin()
	if err != nil {
		return err
	}
	_, err = ofp.Write(pt)

	// read chunks of data and decrypt them,
	// writing the results to the output file
	for err == nil {
		var n int

		n, err = ifp.Read(ct)
		if err == nil {
			pt, err = dec.Update(ct[:n])
			if err == nil {
				_, err = ofp.Write(pt)
			}
		} else if err == io.EOF {
			err = nil
			break
		}
	}

	// finalize the decryption, writing any
	// remaining plain text to the output file
	if err == nil {
		pt, err = dec.End()
		if err == nil {
			_, err = ofp.Write(pt)
		}
	}

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

	// open the input file
	ifp, err := os.Open(params.infile)
	if err != nil {
		return err
	}
	defer ifp.Close()

	// determine the size of the input file
	size, _ := ifp.Seek(0, os.SEEK_END)
	ifp.Seek(0, os.SEEK_SET)

	// don't allow the simple method if the
	// input file is too large
	if params.method == methodSimple && size > maxSimpleSize {
		fmt.Fprintf(os.Stderr, "NOTE: This is only for demonstration purposes and is designed to work on memory\n")
		fmt.Fprintf(os.Stderr, "      constrained devices.  Therefore, this sample application will switch to\n")
		fmt.Fprintf(os.Stderr, "      the chunking APIs for files larger than %v bytes in order to reduce\n", maxSimpleSize)
		fmt.Fprintf(os.Stderr, "      excessive resource usages on resource constrained IoT devices\n")
		params.method = maxSimpleSize
	}

	// create the output file
	ofp, err := os.Create(params.outfile)
	if err != nil {
		return err
	}
	defer ofp.Close()

	// encrypt or decrypt using the specified method
	if params.method == methodSimple {
		if params.mode == modeEncrypt {
			err = simpleEncrypt(credentials, ifp, ofp, size)
		} else /* decrypt */ {
			err = simpleDecrypt(credentials, ifp, ofp, size)
		}
	} else /* chunking */ {
		if params.mode == modeEncrypt {
			err = chunkingEncrypt(credentials, ifp, ofp)
		} else /* decrypt */ {
			err = chunkingDecrypt(credentials, ifp, ofp)
		}
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
