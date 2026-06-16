// Command jwt_credentials demonstrates the JWT flow for structured encryption,
// where the caller already holds a JWT minted by their own IDP integration.
//
// You pass that JWT straight to the JWT-based structured API
// (StructuredEncryptJwt / StructuredDecryptJwt); the SDK does not perform any
// IDP login. The server identifies the user from the token and the IDP
// configuration in Ubiq (ubiq_customer_id).
//
// If you instead want the SDK to log in for you with a username and password,
// see examples/idp_user.
//
// The JWT is read from the environment (it is a short-lived secret, not config).
// To run it, fill in configuration.idp, then:
//
//	export IDP_JWT="eyJ..."
//	go run jwt_credentials.go
package main

import (
	"fmt"
	"log"
	"os"

	"gitlab.com/ubiqsecurity/ubiq-go/v2"
)

const (
	// configFile needs the ubiq_customer_id the token belongs to;
	// no client secret or password is required for this flow.
	configFile = "configuration.idp"

	// envJwt is the environment variable holding the caller's JWT.
	envJwt = "IDP_JWT"

	dataset   = "SSN"
	plaintext = "123-45-6789"
)

func main() {
	config, err := ubiq.NewConfiguration(configFile)
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}

	jwt := os.Getenv(envJwt)
	if jwt == "" {
		log.Fatalf("set %s in the environment to your IDP-issued JWT before running", envJwt)
	}

	ciphertext, err := ubiq.StructuredEncryptJwt(jwt, &config, dataset, plaintext, nil)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	decrypted, err := ubiq.StructuredDecryptJwt(jwt, &config, dataset, ciphertext, nil)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	fmt.Printf("plaintext:  %s\n", plaintext)
	fmt.Printf("ciphertext: %s\n", ciphertext)
	fmt.Printf("decrypted:  %s\n", decrypted)
}
