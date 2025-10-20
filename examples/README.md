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
