package main

import (
	"flag"
	"fmt"
	"gitlab.com/ubiqsecurity/ubiq-go"
	"os"
)

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
	fmt.Fprintf(os.Stderr, "                             the results to the output file\n")
	fmt.Fprintf(os.Stderr, "  -d, -decrypt            Decrypt the contents of the input file and write\n")
	fmt.Fprintf(os.Stderr, "                             the results to the output file\n")
	fmt.Fprintf(os.Stderr, "  -s, -simple             Use the simple encryption / decryption interfaces\n")
	fmt.Fprintf(os.Stderr, "  -p, -pieceswise         Use the piecewise encryption / decryption interfaces\n")
	fmt.Fprintf(os.Stderr, "  -i INFILE, -in INFILE   Set input file name\n")
	fmt.Fprintf(os.Stderr, "  -o OUTFILE, -out OUTFILE\n")
	fmt.Fprintf(os.Stderr, "                           Set output file name\n")
	fmt.Fprintf(os.Stderr, "  -c CREDENTIALS, -creds CREDENTIALS\n")
	fmt.Fprintf(os.Stderr, "                           Set the file name with the API credentials\n")
	fmt.Fprintf(os.Stderr, "                             (default: ~/.ubiq/credentials)\n")
	fmt.Fprintf(os.Stderr, "  -P PROFILE, -profile PROFILE\n")
	fmt.Fprintf(os.Stderr, "                           Identify the profile within the credentials file\n")

	os.Exit(status)
}

func getopts() parameters {
	var help, version bool = false, false
	var encrypt, decrypt bool = false, false
	var simple, piecewise bool = false, false
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
	f.BoolVar(&piecewise, "p", false, "")
	f.BoolVar(&piecewise, "piecewise", false, "")

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

	if (encrypt && decrypt) || (!encrypt && !decrypt) {
		usage("encrypt / decrypt operation not specified")
	} else if encrypt {
		params.mode = modeEncrypt
	} else /* decrypt */ {
		params.mode = modeDecrypt
	}

	if (simple && piecewise) || (!simple && !piecewise) {
		usage("simple / piecewise method not specified")
	} else if simple {
		params.method = methodSimple
	} else /* piecewise */ {
		params.method = methodPiecewise
	}

	if len(params.infile) == 0 {
		usage("input file not specified")
	}

	if len(params.outfile) == 0 {
		usage("output file not specified")
	}

	return params
}
