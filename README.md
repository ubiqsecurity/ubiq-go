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
import "gitlab.com/ubiqsecurity/ubiq-go/v2"
```

Available symbols are in the `ubiq` namespace/package.

>**Note:** If you don't include the `/v2`, you will get the v1 of this library that does not support Structured Encryption. Check your references/imports.

### Requirements

The library has been tested with Go 1.18; however, it may work with
older versions.

## Usage

### Configuration

A configuration can be supplied to control various functions, such as caching timing, security, and how usage is reported back to the ubiq servers. The configuration file can be loaded from an explicit file or read from the default location [`~/.ubiq/configuration`]. If a configuration is not provided, default values will be used. See [below](#configuration-file) for a sample configuration file and content description.

#### Read configuration from default [`~/.ubiq/configuration`] or use default values
```go
config, err := ubiq.NewConfiguration()
```

#### Read configuration from a specific file
```go
config, err := ubiq.NewConfiguration(<path_to_file>)
```

#### Read configuration from JSON String
```go
// Load from ENV variables or hardcoded string
configJson := "{\"logging\": {\"verbose\": true}}"
config, err := ubiq.NewConfigurationFromJson(configJson)
```

### Credentials

The library needs to be configured with your account credentials which are
available in your [Ubiq Dashboard][dashboard] [credentials][credentials]. The
credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).

#### Using CredentialsParams Object
Credentials can be built using explicit parameters using the CredentialsParams object. Set the values you need, and then call `.Build()` to get a Credentials object. 
```go
// Explicitly set values, with config
credParams := ubiq.CredentialsParams{
  AccessKeyId: "...",
  SecretSigningKey: "...",
  SecretCryptoAccessKey: "..."
  
  config: &config
}

// File and Profile
// No config object, will default to ~/.ubiq/credentials or default values.
credParams := ubiq.CredentialsParams{
  CredentialsFile: "/path/to/credentials",
  Profile: "profile-name",
}

// ENV variables 
// (UBIQ_ACCESS_KEY_ID, UBIQ_SECRET_SIGNING_KEY, UBIQ_SECRET_CRYPTO_ACCESS_KEY)
// or default file/profile
credParams := ubiq.CredentialsParams{
  Config: &config,
}

// Build the credentials object!
credentials, err := credParams.Build()
```

> **Note:** Providing a Configuration object during Credentials creation allows you to change the configuration at runtime.
>
>```go
>  config.Logging.Verbose = true
>  config.KeyCaching.TTLSeconds = 30
>```

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

### IDP Integration

Ubiq currently supports both Okta and Entra IDP integration.  Instead of using the credentials provided when creating the API Key, the username (email) and password will be used to authenticate with the IDP and provide access to the Ubiq platform.

Additional server information will be needed in the configuration file, see the [Configuration - IDP Specific Parameters](#idp-specific-parameters) section for more information.

To use IDP, you must use the `CredentialsParam.Build()` method, otherwise your credentials object will not be fully initialized.

#### Examples
```go
// in the credentials file
// [profile-name]
// IDP_USERNAME = ***
// IDP_PASSWORD = ***
credParams := ubiq.CredentialsParams{
  CredentialsFile: "/path/to/credentials",
  Profile: "profile-name",
  Config: &config,
}


// Environment Variables
// UBIQ_IDP_USERNAME
// UBIQ_IDP_PASSWORD
credParams := ubiq.CredentialsParams{
  Config: &config,
}

// Explicitly set credentials
credParams := ubiq.CredentialsParams{
  Config: &config,
  IdpUsername: "***",
  IdpPassword: "***"
}

credentials, err := credParams.Build()

```


## Ubiq Unstructured Encryption/Decryption

Unstructured encryption takes in data and returns a `[]byte` array. 
It is suitable for encrypting files, images, or other miscellaneous data.

### Simple encryption and decryption

#### Encrypt a single block of data

Pass credentials and data into the encryption function. The encrypted data
will be returned.

```go
var pt []byte = ...
ct, err := ubiq.Encrypt(credentials, pt)
```

#### Decrypt a single block of data

Pass credentials and encrypted data into the decryption function. The
plaintext data will be returned.

```go
var ct []byte = ...
pt, err := ubiq.Decrypt(credentials, ct)
```

### Chunking encryption and decryption

#### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed
- Call the encryption instance end method

```go
var pt []byte = make([]byte, 128*1024)

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

### Encrypt and Decrypt with Reuse

To reuse the encryption/decryption objects, initialize them with the credentials object and store them in a variable. Encryption takes an extra parameter, the number of separate encryptions the caller wishes to perform with the key. This number may be limited by the server. 

```go
  encryptor, _ := ubiq.NewEncryption(credentials, 1)
	decryptor, _ := ubiq.NewDecryption(credentials)

	raw_data := [6]string{"alligator", "otter", "eagle owl", "armadillo", "dormouse", "ground hog"}
	bytearr := [][]byte{}
	encrypted_data := bytearr[:]

	for i := range raw_data {
		enc, err := encryptor.Begin()
		t, err := encryptor.Update([]byte(raw_data[i]))
		enc = append(enc, t...)
		t, err = encryptor.End()
		enc = append(enc, t...)
		encrypted_data = append(encrypted_data, enc)
	}

	for i := range encrypted_data {
		decrypted, err := decryptor.Begin()
		t, err := decryptor.Update(encrypted_data[i])
		decrypted = append(decrypted, t...)
		t, err = decryptor.End()
		decrypted = append(decrypted, t...)
		fmt.Fprintf(os.Stdout, "Decrypted: %s \n", string(decrypted[:]))
	}
```

## Ubiq Structured Encryption
This library incorporates Ubiq Structured Encryption.

### Encrypt

Pass credentials, the name of a structured dataaset, and data into the encryption function.
The encrypted data will be returned.

```go
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

### Encrypt for Search

The same plaintext data will result in different cipher text when encrypted using different data keys. The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys. This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```go
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

### Decrypt

Pass credentials, the name of a structured dataset, and data into the decryption function.
The decrypted data will be returned.

```go
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

## Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  

By default, configuration is loaded in from `~/.ubiq/configuration`. If the file does not exist, the default values (show below) will be used.

```json
{
  "event_reporting": {
    "wake_interval": 10,
    "minimum_count": 50,
    "flush_interval": 90,
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
  },
  "idp": {
    "provider": "okta",
    "ubiq_customer_id": "f6f.....08c5",
    "idp_token_endpoint_url": " https://dev-<domain>.okta.com/oauth2/v1/token",
    "idp_tenant_id": "0o....d7",
    "idp_client_secret": "yro.....2Db"
  }
}
```

### Event Reporting
The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>wake_interval</b> indicates the number of seconds to sleep before waking to determine if there has been enough activity to report usage (default: 10 seconds)
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage (defualt: 50 records)
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server. (default: 90 seconds)
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application (default: false)
- <b>timestamp_granularity</b> indicates the how granular the timestamp will be when reporting events. (default: MICROS) Valid values are
  - "MICROS"  
    - DEFAULT: values are reported down to the microsecond resolution when possible
  - "MILLIS"  
    - values are reported to the millisecond
  - "SECONDS"  
    - values are reported to the second
  - "MINUTES"  
    - values are reported to minute
  - "HOURS"  
    - values are reported to hour
  - "HALF_DAYS"  
    - values are reported to half day
  - "DAYS"  
    - values are reported to the day

### Key Caching
The <b>key_caching</b> section contains values to control how and when keys are cached.

- <b>unstructured</b> indicates whether keys will be cached when doing unstructured decryption. (default: true)
- <b>structured</b> indicates whether keys will be cached when doing structured encryption/decryption. (default: true)
- <b>encrypt</b> indicates if keys should be stored encrypted. If keys are encrypted, they will be harder to access via memory, but require them to be decrypted with each use. (default: false)
- <b>ttl_seconds</b> how many seconds before cache entries should expire and be re-retrieved (default: 1800 seconds)

### Logging
The <b>logging</b> section contains values to control logging levels.

- <b>verbose</b> enables and disables logging output like event processing and caching. (default: false)

### IDP specific parameters
- <b>provider</b> indicates the IDP provider, either <b>okta</b> or <b>entra</b>
- <b>ubiq_customer_id</b> The UUID for this customer.  Will be provided by Ubiq.
- <b>idp_token_endpoint_url</b> The endpoint needed to authenticate the user credentials, provided by Okta or Entra
- <b>idp_tenant_id</b> contains the tenant value provided by Okta or Entra
- <b>idp_client_secret</b> contains the client secret value provided by Okta or Entra

### Custom Metadata for Usage Reporting
There are cases where a developer would like to attach metadata to usage information reported by the application.  Both the structured and unstructured interfaces allow user_defined metadata to be sent with the usage information reported by the libraries.

The **add_reporting_user_defined_metadata** function accepts a string in JSON format that will be stored in the database with the usage records.  The string must be less than 1024 characters and be a valid JSON format.  The string must include both the `{` and `}` symbols.  The supplied value will be used until the object goes out of scope.  Due to asynchronous processing, changing the value may be immediately reflected in subsequent usage.  If immediate changes to the values are required, it would be safer to create a new encrypt / decrypt object and call the `add_reporting_user_defined_metadata` function with the new values.

>Note: User Defined Metadata is only available when using the full encryption objects instead of the simple methods.

Examples are shown below.

```go
    # Unstructured
    ...
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