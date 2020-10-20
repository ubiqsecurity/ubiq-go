# Ubiq Security Sample Application using Go Library

This sample application will demonstrate how to encrypt and decrypt data using the different APIs.

### Documentation

See the [Go API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Make sure Go is installed on your system.

```sh
$ sudo apt install golang
```

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard

<pre>
[default]
ACCESS_KEY_ID = ...  
SECRET_SIGNING_KEY = ...  
SECRET_CRYPTO_ACCESS_KEY = ...  
</pre>

## Build the examples

Create a local directory and compile the example application

```sh
$ git clone https://gitlab.com/ubiqsecurity/ubiq-go.git
$ cd ubiq-go/examples
$ go build ubiq_sample.go
```

## View Program Options

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
  -p, -pieceswise         Use the piecewise encryption / decryption interfaces
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

#### Demonstrate using the piecewise (-p / -piecewise) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ ./ubiq_sample -i README.md -o /tmp/readme.enc -e -p -c ./credentials
```

#### Demonstrate using the piecewise (-p / -piecewise) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ ./ubiq_sample -i /tmp/readme.enc -o /tmp/README.out -d -p -c ./credentials
```
