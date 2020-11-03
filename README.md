# Ubiq Security Go Library

The Ubiq Security Go library provides convenient interaction with the
Ubiq Security Platform API for applications written Go. It includes a
pre-defined set of functions and classes that will provide simple interfaces
to encrypt and decrypt data

## Documentation

See the [Go API docs](https://dev.ubiqsecurity.com/docs/api) and
[below](#usage) for examples.

Individual interfaces are documented in greater detail in the source
code which can be viewed using the `go doc` tool.

## Building from source:

Import the Ubiq Go library in your source files:
```go
import "gitlab.com/ubiqsecurity/ubiq-go"
```

Available symbols are in the `ubiq` namespace/package.

### Requirements

The library has been tested with Go 1.10; however, it may work with
older versions.

## Usage

### Credentials

The library needs to be configured with your account credentials which are
available in your [Ubiq Dashboard][dashboard] [credentials][credentials]. The
credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).

#### Read credentials from a specific file and use a specific profile
```go
credentials, err := ubiq.NewCredentials(
        "/path/to/credentials", "profile-name")
```

#### Read credentials from ~/.ubiq/credentials and use the default profile
```go
credentials, err := ubiq.NewCredentials()
```

#### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID  
UBIQ_SECRET_SIGNING_KEY  
UBIQ_SECRET_CRYPTO_ACCESS_KEY  
```go
credentials, err := ubiq.NewCredentials()
```

#### Explicitly set the credentials
```go
credentials, err := ubiq.NewCredentials(
        "..." /* access key id */,
        "..." /* secret signing key */,
        "..." /* secret crypto access key */,
        "..." /* Ubiq API server, may omit this parameter */)
```


### Simple encryption and decryption

#### Encrypt a single block of data

Pass credentials and data into the encryption function. The encrypted data
will be returned.

```go
var pt []byte = ...
credentials, err := ubiq.NewCredentials()
ct, err := ubiq.Encrypt(credentials, pt)
```

#### Decrypt a single block of data

Pass credentials and encrypted data into the decryption function. The
plaintext data will be returned.

```go
var ct []byte = ...
credentials, err := ubiq.NewCredentials()
pt, err := ubiq.Decrypt(credentials, ct)
```

### Piecewise encryption and decryption

#### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed
- Call the encryption instance end method

```go
var pt []byte = make([]byte, 128*1024)

credentials, _ := ubiq.NewCredentials()
encryption, _ := ubiq.NewEncryption(credentials, 1)
defer encryption.Close()

ct, _ := encryption.Begin()
for {
        n, e := infile.Read(pt)
        if e == io.EOF {
                break
        }
        t, _ := encryption.Update(pt[:n])
        ct = append(ct, t...)
}
t, _ := encryption.End()
ct = append(ct, t...)
```

#### Decrypt a large data element where data is loaded in chunks

- Create an instance of the decryption object using the credentials.
- Call the decryption instance begin method
- Call the decryption instance update method repeatedly until all the data is processed
- Call the decryption instance end method

```go
var ct []byte = make([]byte, 128*1024)

credentials, _ := ubiq.NewCredentials()
decryption, _ := ubiq.NewDecryption(credentials)
defer decryption.Close()

pt, _ := decryption.Begin()
for {
        n, e := infile.Read(ct)
        if e == io.EOF {
                break
        }
        t, _ := decryption.Update(ct[:n])
        pt = append(pt, t...)
}
t, _ := decryption.End()
pt = append(pt, t...)
```

[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
