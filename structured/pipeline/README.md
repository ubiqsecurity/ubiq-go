# Structured Pipeline Architecture

A modular pipeline architecture for structured (format-preserving) encryption in the Ubiq Go SDK.

## Overview

The pipeline architecture breaks down encryption/decryption into discrete, testable operations that can be composed into pipelines. Each operation transforms input data and passes it to the next operation in the chain.

## Package Structure

```
structured/pipeline/
├── operation.go          # Core types (Operation, OperationContext, DatasetInfo)
├── pipeline.go           # Pipeline executor
├── exec/
│   └── executor.go       # High-level Encrypt/Decrypt functions
└── operations/
    ├── convert_radix.go        # Character set conversion
    ├── encode_key_number.go    # Embed key number in ciphertext
    ├── decode_key_number.go    # Extract key number from ciphertext
    ├── trim_prefix.go          # Remove prefix before encryption
    ├── expand_prefix.go        # Restore prefix after encryption
    ├── trim_suffix.go          # Remove suffix before encryption
    ├── expand_suffix.go        # Restore suffix after encryption
    ├── trim_passthrough.go     # Remove passthrough chars, create template
    ├── expand_passthrough.go   # Restore passthrough chars from template
    ├── encode_input.go         # Base32/Base64 encoding
    ├── decode_input.go         # Base32/Base64 decoding
    ├── pad_input.go            # Left-pad to minimum length
    ├── unpad_input.go          # Remove padding
    └── *_test.go               # Unit tests (50+ tests)
```

## Core Types

### Operation Interface

```go
type Operation interface {
    Invoke(ctx *OperationContext) (string, error)
}
```

### OperationContext

Carries state through the pipeline:

```go
type OperationContext struct {
    Dataset       *DatasetInfo       // Dataset configuration
    KeyNumber     *int               // Encryption key number
    OriginalValue string             // Initial input (immutable)
    CurrentValue  string             // Value being transformed
    IsEncrypt     bool               // true = encrypt, false = decrypt
    Tweak         []byte             // FF1 tweak
    Data          map[string]string  // Cross-operation communication
}
```

### DatasetInfo

Dataset configuration used by operations:

```go
type DatasetInfo struct {
    Name                  string
    Algorithm             string
    InputCharacterSet     string
    OutputCharacterSet    string
    PassthroughCharacters string
    InputLengthMin        int
    InputLengthMax        int
    NumEncodingBits       int
    // ... plus alphabet pointers and passthrough rules
}
```

## Usage

### High-Level API (exec package)

```go
import "gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline/exec"

// Encrypt
ciphertext, err := exec.Encrypt(datasetInfo, plaintext, tweak, keyNumber, algorithm)

// Decrypt
plaintext, keyNumber, err := exec.Decrypt(datasetInfo, ciphertext, tweak, algorithmFactory)
```

### Building Custom Pipelines

```go
import (
    "gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
    "gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline/operations"
)

// Create pipeline with operations
p := pipeline.NewPipeline(
    operations.NewTrimPrefixOperation(3),
    operations.NewTrimPassthroughOperation(),
)

// Execute
ctx := pipeline.NewOperationContext(dataset, input, true, tweak)
result, err := p.Invoke(ctx)
```

## Encryption Flow

```
Input: "ABC-123-456-XYZ"
         │
         ▼
┌─────────────────────┐
│ 1. Trim Prefix      │  Removes "ABC", stores in ctx.Data["Prefix"]
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 2. Trim Suffix      │  Removes "XYZ", stores in ctx.Data["Suffix"]
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 3. Trim Passthrough │  Removes "-", creates template "0-000-000-0"
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 4. FF1 Encrypt      │  Format-preserving encryption
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 5. Convert Radix    │  Input charset → Output charset
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 6. Encode Key Num   │  Embeds key number in first character
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 7. Expand Passthru  │  Restores "-" using template
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 8. Expand Suffix    │  Restores "XYZ"
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ 9. Expand Prefix    │  Restores "ABC"
└─────────────────────┘
         │
         ▼
Output: "ABC-789-012-XYZ"
```

## Running Tests

```bash
# All pipeline tests
go test ./structured/pipeline/...

# Verbose output
go test -v ./structured/pipeline/operations/...

# Specific test
go test -v -run TestTrimPassthrough ./structured/pipeline/operations/
```
