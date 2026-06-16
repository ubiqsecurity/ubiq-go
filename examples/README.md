# Ubiq Security Sample Application using Go Library

This sample applications will demonstrate how to perform both structured and unstructured encrypt and decrypt data using the different APIs.

### Documentation

See the [Go API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Make sure Go is installed on your system.

On Debian and Debian-like Linux systems:
```sh
$ sudo apt install golang
```

For MacOS, Windows, and other Linux systems, see the
[Go installation page](https://golang.org/doc/install).

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard

<pre>
[default]
ACCESS_KEY_ID = ...  
SECRET_SIGNING_KEY = ...  
SECRET_CRYPTO_ACCESS_KEY = ...  
</pre>

## Examples

There are separate examples for structured encryption and unstructured encryption.  Each example is within its own directory.

### Unstructured Encryption

```sh
$ git clone https://gitlab.com/ubiqsecurity/ubiq-go.git
$ cd ubiq-go/examples/unstructured
$ go get
$ go build ubiq_sample.go
```

Older versions of Go may produce a message like the following:
```
go get: no install location for directory /path/to/ubiq-go/examples outside GOPATH
	For more details see: 'go help gopath'
```
This can be safely ignored for the purpose of building the example.

### View Program Options

From within the examples directory

```sh
$ ./ubiq_sample -h
```
<pre>
Usage: ./ubiq_sample -e|-d -s|-p -i INFILE -o OUTFILE
Encrypt or decrypt files using the Ubiq service

  -h, -help               Show this help message and exit
  -V, -version            Show program's version number and exit
  -e, -encrypt            Encrypt the contents of the input file and write
                            the results to the output file
  -d, -decrypt            Decrypt the contents of the input file and write
                            the results to the output file
  -s, -simple             Use the simple encryption / decryption interfaces
  -p, -chunking           Use the encryption / decryption interfaces to handle
                              large data elements where data is loaded in chunks
  -i INFILE, -in INFILE   Set input file name
  -o OUTFILE, -out OUTFILE
                          Set output file name
  -c CREDENTIALS, -creds CREDENTIALS
                          Set the file name with the API credentials
                            (default: ~/.ubiq/credentials)
  -P PROFILE, -profile PROFILE
                          Identify the profile within the credentials file
</pre>

#### Demonstrate using the simple (-s / -simple) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ ./ubiq_sample -i README.md -o /tmp/readme.enc -e -s -c ./credentials
```

#### Demonstrate using the simple (-s / -simple) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ ./ubiq_sample -i /tmp/readme.enc -o /tmp/README.out -d -s -c ./credentials
```

#### Demonstrate using the chunking (-p / -chunking) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ ./ubiq_sample -i README.md -o /tmp/readme.enc -e -p -c ./credentials
```

#### Demonstrate using the chunking (-p / -chunking) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ ./ubiq_sample -i /tmp/readme.enc -o /tmp/README.out -d -p -c ./credentials
```

### Structured Encryption

```sh
$ git clone https://gitlab.com/ubiqsecurity/ubiq-go.git
$ cd ubiq-go/examples/structured
$ go get
$ go build ubiq_structured_sample.go
```

Older versions of Go may produce a message like the following:
```
go get: no install location for directory /path/to/ubiq-go/examples outside GOPATH
	For more details see: 'go help gopath'
```
This can be safely ignored for the purpose of building the example.

### View Program Options

From within the examples directory

```sh
$ ./ubiq_structured_sample -h
```
<pre>
Encrypt or decrypt text using the Ubiq service
 Options:
  -h, -help               Show this help message and exit
  -V, -version            Show program's version number and exit
  -e, -encrypttext        Set the field text value to encrypt and will
                            return the encrypted cipher text.
  -d, -decrypttext        Set the cipher text value to decrypt and will
                            return the decrypted text.
  -n, -datasetName        Set the name of the dataset, for example SSN.
  -c CREDENTIALS, -creds CREDENTIALS
                          Set the file name with the API credentials
                            (default: ~/.ubiq/credentials)
  -P PROFILE, -profile PROFILE
                          Identify the profile within the credentials file
  -s, -search            Perform an Encrypt For Search.  Only compatible with the -e option
</pre>

#### Example encrypting a simple text string using the SSN dataset and returning the ciphertext

```sh
$ ./ubiq_structured_sample -c ./credentials -P default -n SSN -e 123-45-6789
```

#### Example decrypting a ciphertext string using the SSN dataset and returning the original plaintext

```sh
$ ./ubiq_structured_sample -c credentials -P unittest -n SSN -d 200-0N-nphF
```

#### Example encrypting a simple text string using the SSN dataset and the EncryptForSearch capability and returning different ciphertexts

```sh
$ ./ubiq_structured_sample -c ./credentials -P default -n SSN -e 123-45-6789 -s
```

### IDP-based Structured Encryption

These examples authenticate through an Identity Provider instead of static API
credentials. Each is kept deliberately short: the inputs live in a JSON
configuration file (and a couple of `const` values at the top of each program),
so the file reads as a straight-line demonstration of the SDK calls. Edit the
config and constants, then `go run` it.

There are three flavors:

- Self-signed ("Ubiq" provider), where the library mints and signs a short-lived
  token locally, see `examples/self_signed`.
- External IDP (Okta / Entra) with a username and password, where the SDK logs
  in for you, see `examples/idp_user`.
- External IDP JWT, where you already hold a JWT and hand it to the SDK, see
  `examples/jwt_credentials`.

#### Self-Signed IDP

With the self-signed provider no external IDP login happens. The library signs a
short-lived RS256 token locally with your RSA private key and exchanges it at the
Ubiq SSO endpoint for an API certificate. The identity becomes the token's
`email` claim, which the server matches against the user (or API key)
under the configured `ubiq_customer_id`.

The RSA key pair is created for you when you enable self-signed IDP in the Ubiq
dashboard: the public key is registered with Ubiq and the private key is
shown to you once. Save that private key (Ubiq does not keep a copy) as
`selfsign_priv.pem` next to the example. Do not generate your own key here: a key
whose public half is not registered with Ubiq will fail verification.

Edit `configuration.selfsigned` (provider + `ubiq_customer_id`) and the constants at
the top of `self_signed.go` (`identity`, `dataset`, `plaintext`), then run it:

```sh
$ cd ubiq-go/examples/self_signed
$ go run self_signed.go
```

The configuration file is just the provider and the `ubiq_customer_id`
(`configuration.selfsigned` in this directory is a starting point):

```json
{
  "idp": {
    "provider": "ubiq",
    "ubiq_customer_id": "REPLACE-WITH-YOUR-UBIQ-CUSTOMER-UUID"
  }
}
```

#### External IDP (username + password)

Here the SDK does the IDP login for you. `CredentialsParams.Build()` reads
`IDP_USERNAME` / `IDP_PASSWORD` from a credentials file, performs an OAuth
password-grant login against the configured IDP, exchanges the result for an API
certificate, and returns Credentials usable with the regular structured API.

The password lives in the credentials file (not in source). Fill in
`configuration.idp` (provider, tenant id, client secret, token endpoint,
`ubiq_customer_id`) and the `credentials` file (`IDP_USERNAME` / `IDP_PASSWORD`),
then run it:

```sh
$ cd ubiq-go/examples/idp_user
$ go run idp_user.go
```

The credentials file is the usual INI format with the IDP login under a profile:

```ini
[default]
IDP_USERNAME = user@example.com
IDP_PASSWORD = REPLACE-WITH-YOUR-IDP-PASSWORD
```

#### External IDP (JWT)

Use this when your application already has a JWT from its own IDP integration.
You pass the JWT straight to the JWT-based structured API
(`StructuredEncryptJwt` / `StructuredDecryptJwt`); the SDK performs no login. The
configuration only needs the `ubiq_customer_id` the token belongs to.

The JWT is read from the environment (it is a short-lived secret, not config):

```sh
$ cd ubiq-go/examples/jwt_credentials
$ export IDP_JWT="eyJ..."
$ go run jwt_credentials.go
```
