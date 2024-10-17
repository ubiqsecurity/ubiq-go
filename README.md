# Ubiq Security Go Library

The Ubiq Security Go library provides convenient interaction with the
Ubiq Security Platform API for applications written Go. It includes a
pre-defined set of functions and classes that will provide simple interfaces
to encrypt and decrypt data

> This repository is hosted at [Gitlab][repository] and mirrored elsewhere.
>
> To contribute or report an issue, please make requests there.

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

The library has been tested with Go 1.18; however, it may work with
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

### Structured Encryption
This library incorporates Ubiq Structured Encryption.

#### Encrypt

Pass credentials, the name of a structured dataaset, and data into the encryption function.
The encrypted data will be returned.

```go
credentials, _ := ubiq.NewCredentials()

datasetName := "SSN"
plainText := "999-01-2345"

enc, err := ubiq.NewStructuredEncryption(creds)
if err != nil {
    return err
}
cipherText, err := enc.Cipher(datasetName, plainText, nil)
if err != nil {
    return err
}
fmt.Fprintf(os.Stdout, "ENCRYPTED cipher= %s \n", cipherText)
return err
```

#### Encrypt for Search

The same plaintext data will result in different cipher text when encrypted using different data keys. The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys. This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```go
credentials, _ := ubiq.NewCredentials()

datasetName := "SSN"
plainText := "999-01-2345"

enc, err := ubiq.NewStructuredEncryption(creds)
if err != nil {
    return err
}
cipherTextArr, err := enc.CipherForSearch(datasetName, plainText, nil)
if err != nil {
    return err
}

fmt.Fprintf(os.Stdout, "ENCRYPTED cipher= %v \n", cipherTextArr)
// ENCRYPTED cipher= ["000-03-OJMp", "100-0B-dnKG", "200-12-NOx5", "300-0j-esgH"]
```

#### Decrypt

Pass credentials, the name of a structured dataset, and data into the decryption function.
The decrypted data will be returned.

```go
credentials, _ := ubiq.NewCredentials()

datasetName := "SSN"
cipherText := "300-0E-274t"

dec, err := ubiq.NewStructuredDecryption(creds)
if err != nil {
    return err
}
plainText, err := dec.Cipher(datasetName, cipherText, nil)
if err != nil {
    return err
}

fmt.Fprintf(os.Stdout, "DECRYPTED decrypted_text= %s \n", plainText)
```

### Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  

#### Event Reporting
The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>wake_interval</b> indicates the number of seconds to sleep before waking to determine if there has been enough activity to report usage
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server.
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application
- <b>timestamp_granularity</b> indicates the how granular the timestamp will be when reporting events.  Valid values are
  - "MICROS"  
    // DEFAULT: values are reported down to the microsecond resolution when possible
  - "MILLIS"  
  // values are reported to the millisecond
  - "SECONDS"  
  // values are reported to the second
  - "MINUTES"  
  // values are reported to minute
  - "HOURS"  
  // values are reported to hour
  - "HALF_DAYS"  
  // values are reported to half day
  - "DAYS"  
  // values are reported to the day

#### Key Caching
The <b>key_caching</b> section contains values to control how and when keys are cached.

- <b>unstructured</b> indicates whether keys will be cached when doing unstructured decryption. (default: true)
- <b>structured</b> indicates whether keys will be cached when doing structured encryption/decryption. (default: true)
- <b>encrypt</b> indicates if keys should be stored encrypted. If keys are encrypted, they will be harder to access via memory, but require them to be decrypted with each use. (default: false)
- <b>ttl_seconds</b> how many seconds before cache entries should expire and be re-retrieved (default: 1800)

#### Logging
The <b>logging</b> section contains values to control logging levels.

- <b>verbose</b> enables and disables logging output like event processing and caching.


```json
{
  "event_reporting": {
    "wake_interval": 1,
    "minimum_count": 2,
    "flush_interval": 2,
    "trap_exceptions": false,
    "timestamp_granularity" : "MICROS"
  },
  "key_caching":{
    "unstructured": true,
    "structured": true,
    "encrypt": false,
    "ttl_seconds": 1800
  },
  "logging": {
    "verbose": true
  }
}
```

### Custom Metadata for Usage Reporting
There are cases where a developer would like to attach metadata to usage information reported by the application.  Both the structured and unstructured interfaces allow user_defined metadata to be sent with the usage information reported by the libraries.

The **add_reporting_user_defined_metadata** function accepts a string in JSON format that will be stored in the database with the usage records.  The string must be less than 1024 characters and be a valid JSON format.  The string must include both the `{` and `}` symbols.  The supplied value will be used until the object goes out of scope.  Due to asynchronous processing, changing the value may be immediately reflected in subsequent usage.  If immediate changes to the values are required, it would be safer to create a new encrypt / decrypt object and call the `add_reporting_user_defined_metadata` function with the new values.

>Note: User Defined Metadata is only available when using the full encryption objects instead of the simple methods.

Examples are shown below.

```go
    # Unstructured
    ...
    credentials, _ := ubiq.NewCredentials()
    encryption, err := ubiq.NewEncryption(credentials, 1)
    if err == nil {
    defer encryption.Close()
    encryption.AddUserDefinedMetadata("{\"some_meaningful_flag\" : true }")

    ct, _ := encryption.Begin()
    ...

    # Unstructured Encrypt operations
```
```go
    # Structured
    ...
    credentials, _ := ubiq.NewCredentials()
    dec, err := NewStructuredDecryption(c)
    dec.AddUserDefinedMetadata("{\"some_meaningful_flag\" : true }")
	if err == nil {
		defer dec.Close()
		pt, err = dec.Cipher(dataset, ct, twk)
    ...
  # FPE Encrypt and Decrypt operations
```

## Ubiq API Error Reference

Occasionally, you may encounter issues when interacting with the Ubiq API. 

| Status Code | Meaning | Solution |
|---|---|---|
| 400 | Bad Request | Check name of datasets and credentials are complete. |
| 401 | Authentication issue | Check you have the correct API keys, and it has access to the datasets you are using.  Check dataset name. |
| 426 | Upgrade Required | You are using an out of date version of the library, or are trying to use newer features not supported by the library you are using.  Update the library and try again.
| 429 | Rate Limited | You are performing operations too quickly. Either slow down, or contact support@ubiqsecurity.com to increase your limits. | 
| 500 | Internal Server Error | Something went wrong. Contact support if this persists.  | 
| 504 | Internal Error | Possible API key issue.  Check credentials or contact support.  | 

[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/api-keys
[repository]:https://gitlab.com/ubiqsecurity/ubiq-go