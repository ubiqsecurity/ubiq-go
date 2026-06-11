// Command jwt_credentials is a small testing helper for the JWT-based
// structured encryption API. It mirrors the Java "jwt-credentials" tool
// (App.java) and supports two modes:
//
//   - SSO mode (-sso): perform an OAuth password-grant login against the
//     configured external IDP (okta/entra) and print the resulting JWT access
//     token. The token can then be passed to the encrypt/decrypt mode or used
//     in tests.
//
//   - Encrypt/decrypt mode (-encrypt_jwt / -decrypt_jwt): encrypt a value with
//     one user's JWT and decrypt it with another's, exercising the JWT-based
//     structured API across permission boundaries.
//
// As in the Java tool, the -user, -password and -server options name the
// environment variables that hold the actual values (not the values
// themselves), so the same users.env workflow applies.
//
// Examples:
//
//	jwt_credentials -sso -user RW_USER -password RW_PASSWORD -c ./configuration.okta
//	jwt_credentials -encrypt_jwt "$RW_JWT" -decrypt_jwt "$RO_JWT" -c ./configuration.okta -d SSN -i 123-45-6789
package main

import (
	"flag"
	"fmt"
	"os"

	"gitlab.com/ubiqsecurity/ubiq-go/v2"
)

const (
	exitSuccess int = 0
	exitFailure int = 1
)

type parameters struct {
	sso                           bool
	user, password, server        string
	encryptJwt, decryptJwt        string
	configuration, dataset, input string
}

func usage(args ...string) {
	status := exitSuccess
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n\n", args[0])
		status = exitFailure
	}

	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Mint a JWT via IDP SSO, or encrypt/decrypt with JWTs.\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -h, -help                 Show this help message and exit\n")
	fmt.Fprintf(os.Stderr, "  -s, -sso                  Perform an SSO login to get the JWT for the supplied user\n")
	fmt.Fprintf(os.Stderr, "  -u, -user NAME            Name of the ENV variable holding the IDP username (for -sso)\n")
	fmt.Fprintf(os.Stderr, "  -p, -password NAME        Name of the ENV variable holding the IDP password (for -sso)\n")
	fmt.Fprintf(os.Stderr, "  -S, -server NAME          Name of the ENV variable holding the Ubiq server (optional)\n")
	fmt.Fprintf(os.Stderr, "  -encrypt_jwt JWT          JWT for a user permitted to encrypt data\n")
	fmt.Fprintf(os.Stderr, "  -decrypt_jwt JWT          JWT for a user permitted to decrypt data\n")
	fmt.Fprintf(os.Stderr, "  -c, -configuration FILE   Pathname of the IDP configuration file\n")
	fmt.Fprintf(os.Stderr, "  -d, -dataset NAME         Name of the dataset to use, for example SSN\n")
	fmt.Fprintf(os.Stderr, "  -i, -input VALUE          Value to encrypt using the supplied JWTs\n")

	os.Exit(status)
}

func getopts() parameters {
	var help bool
	var params parameters

	flag.BoolVar(&help, "h", false, "")
	flag.BoolVar(&help, "help", false, "")

	flag.BoolVar(&params.sso, "s", false, "")
	flag.BoolVar(&params.sso, "sso", false, "")

	flag.StringVar(&params.user, "u", "", "")
	flag.StringVar(&params.user, "user", "", "")
	flag.StringVar(&params.password, "p", "", "")
	flag.StringVar(&params.password, "password", "", "")
	flag.StringVar(&params.server, "S", "", "")
	flag.StringVar(&params.server, "server", "", "")

	flag.StringVar(&params.encryptJwt, "encrypt_jwt", "", "")
	flag.StringVar(&params.decryptJwt, "decrypt_jwt", "", "")

	flag.StringVar(&params.configuration, "c", "", "")
	flag.StringVar(&params.configuration, "configuration", "", "")
	flag.StringVar(&params.dataset, "d", "", "")
	flag.StringVar(&params.dataset, "dataset", "", "")
	flag.StringVar(&params.input, "i", "", "")
	flag.StringVar(&params.input, "input", "", "")

	flag.Usage = func() { usage() }
	flag.Parse()

	if help {
		usage()
	}

	if params.configuration == "" {
		usage("Must specify the configuration file")
	}

	if params.sso {
		if params.user == "" || params.password == "" {
			usage("SSO requires both -user and -password (ENV variable names)")
		}
	} else {
		if params.encryptJwt == "" || params.decryptJwt == "" {
			usage("Both -encrypt_jwt and -decrypt_jwt must be provided")
		}
		if params.dataset == "" || params.input == "" {
			usage("JWT encrypt/decrypt requires both -dataset and -input")
		}
	}

	return params
}

func main() {
	params := getopts()

	config, err := ubiq.NewConfiguration(params.configuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(exitFailure)
	}

	if params.sso {
		jwt, err := ubiq.IdpLoginJwt(
			os.Getenv(params.user),
			os.Getenv(params.password),
			&config,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error performing SSO login: %v\n", err)
			os.Exit(exitFailure)
		}
		fmt.Println(jwt)
		return
	}

	cipherText, err := ubiq.StructuredEncryptJwt(
		params.encryptJwt, &config, params.dataset, params.input, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting with encrypt_jwt: %v\n", err)
		os.Exit(exitFailure)
	}

	plainText, err := ubiq.StructuredDecryptJwt(
		params.decryptJwt, &config, params.dataset, cipherText, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting with decrypt_jwt: %v\n", err)
		os.Exit(exitFailure)
	}

	fmt.Printf("Original Value: %s\n", params.input)
	fmt.Printf("Encrypted using encrypt_jwt: %s\n", cipherText)
	fmt.Printf("Decrypted using decrypt_jwt: %s\n", plainText)
}
