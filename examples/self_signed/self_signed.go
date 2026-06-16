// Command self_signed demonstrates the self-signed ("Ubiq" provider) IDP flow
// for structured encryption.
//
// Unlike the external-IDP JWT flow (see examples/jwt_credentials), no OAuth
// round trip happens: the library mints a short-lived RS256 token locally,
// signs it with your RSA private key, and exchanges it at the Ubiq SSO endpoint
// for an API certificate. From there the returned Credentials work with the
// regular StructuredEncryption / StructuredDecryption API.
//
// The identity is placed into the token's "email" claim, which the server uses
// to find the matching user (or API key) under the configured
// ubiq_customer_id.
//
// To run it, edit the constants below (and configuration.selfsigned), provide
// an RSA private key PEM, then:
//
//	go run self_signed.go
package main

import (
	"fmt"
	"log"
	"os"

	"gitlab.com/ubiqsecurity/ubiq-go/v2"
)

const (
	// configFile sets provider ("ubiq") and ubiq_customer_id.
	configFile = "configuration.selfsigned"
	// keyFile is the RSA private key (PEM) used to sign the local token. This is
	// the private key the Ubiq dashboard showed you once when you enabled
	// self-signed IDP; its public half is registered with Ubiq. Do not
	// generate a new key here. Keeping it in its own file avoids escaping PEM
	// into JSON.
	keyFile = "selfsign_priv.pem"
	// identity becomes the token's email claim (the user to match).
	identity = "user@example.test"

	dataset   = "SSN"
	plaintext = "123-45-6789"
)

func main() {
	config, err := ubiq.NewConfiguration(configFile)
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}

	keyPem, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("read self-sign key: %v", err)
	}
	config.Idp.SelfSignKey = string(keyPem)

	// Build mints the local token and exchanges it for an API cert.
	creds, err := (&ubiq.CredentialsParams{IdpUsername: identity, Config: &config}).Build()
	if err != nil {
		log.Fatalf("build self-signed credentials: %v", err)
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
