// Command idp_user demonstrates the external-IDP (Okta / Entra) username +
// password flow for structured encryption.
//
// Here the SDK performs the IDP login for you: CredentialsParams.Build() reads
// the IDP username and password from the credentials file, runs an OAuth
// password-grant login against the IDP described in the configuration file,
// exchanges the result for an API certificate, and returns Credentials that
// work with the regular StructuredEncryption / StructuredDecryption API.
//
// Contrast this with examples/jwt_credentials, where the caller already holds a
// JWT (minted elsewhere) and passes it straight to the *Jwt API.
//
// The password lives in the credentials file, not in source. To run it, fill in
// configuration.idp and the credentials file, then:
//
//	go run idp_user.go
package main

import (
	"fmt"
	"log"

	"gitlab.com/ubiqsecurity/ubiq-go/v2"
)

const (
	// configFile carries the IDP settings: provider (okta/entra), tenant id,
	// client secret, token endpoint url, and ubiq_customer_id.
	configFile = "configuration.idp"

	// credentialsFile holds IDP_USERNAME and IDP_PASSWORD under the given
	// profile. Keep your real password out of version control.
	credentialsFile = "credentials"
	profile         = "default"

	dataset   = "SSN"
	plaintext = "123-45-6789"
)

func main() {
	config, err := ubiq.NewConfiguration(configFile)
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}

	// Build reads IDP_USERNAME / IDP_PASSWORD from the credentials file, logs
	// in to the IDP, and exchanges the token for an API certificate.
	creds, err := (&ubiq.CredentialsParams{
		CredentialsFile: credentialsFile,
		Profile:         profile,
		Config:          &config,
	}).Build()
	if err != nil {
		log.Fatalf("build IDP credentials: %v", err)
	}

	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		log.Fatalf("new structured encryption: %v", err)
	}
	defer enc.Close()

	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		log.Fatalf("new structured decryption: %v", err)
	}
	defer dec.Close()

	ciphertext, err := enc.Cipher(dataset, plaintext, nil)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	decrypted, err := dec.Cipher(dataset, ciphertext, nil)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	fmt.Printf("plaintext:  %s\n", plaintext)
	fmt.Printf("ciphertext: %s\n", ciphertext)
	fmt.Printf("decrypted:  %s\n", decrypted)
}
