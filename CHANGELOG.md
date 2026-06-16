# Changelog

# 2.4.0 - 2026-06-15
* Added JWT IDP authentication and the JWT-keyed structured API (StructuredEncryptJwt, StructuredDecryptJwt, and related functions)
* Added self-signed ("Ubiq" provider) IDP authentication
* Added IDP credentials via the credentials file, environment variables, and CredentialsParams
* Added runnable examples for the self-signed, username/password, and JWT IDP flows

# 2.3.1 - 2026-06-17
* Fixed an out-of-charset panic by validating input against the dataset character set before FF1 encryption

# 2.3.0 - 2026-02-26
* Added support for new data types: int32, int64, date, datetime, generic_string, and token
* Added pipeline architecture for structured encryption operations
* Added input padding and input encoding support
* Fixed CipherForSearch for datasets using input encoding

# 2.2.9 - 2025-11-12
* Fixed panic when decrypting invalid strings with large alphabet datasets (>62 characters)
* Fixed panic when decrypting empty strings

# 2.2.8 - 2025-11-04
* Improved error handling for issues when decrypting invalid strings

# 2.2.7 - 2025-10-16
* Added LoadCache method to pre-load and refresh structured encryption and decryption cache on demand
* Updated structured encryption to match algorithms in Second Public Draft - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1.2pd.pdf

# 2.2.6 - 2025-09-16
* Adjust Cache implemenmtation for better stability

# 2.2.5 - 2025-07-02
* Add configuration for max cache size

# 2.2.4 - 2025-06-26
* Fixed caching error when decrypting unstructured data
* Updated Structured encryption to be thread-safe
* Added thread-safe version of Unstructured encryption

# 2.2.3 - 2025-06-05
* Refined project files for future releases

# 2.2.2 - 2025-03-14
* Added support for IDP integration using Okta and Entra

# 2.2.1 - 2025-01-27
* Add support for a dynamic/non-default configuration file or configuration object

## 2.2.0 - 2024-05-29
* Add partial encryption support

## 0.0.3 / 2.0.0 - 2023-09-20
* Add support for Structured Encryption

## 0.0.2 - 2020-10-28
* Update build instructions
* Add support for older Go versions (tested with 1.10)
* Change to MIT license

## 0.0.1 - 2020-10-14
* Initial Version
