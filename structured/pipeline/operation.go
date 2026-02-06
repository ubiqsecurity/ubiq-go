// Package pipeline provides a modular pipeline architecture for structured encryption.
// Each transformation step is an Operation that can be composed into pipelines.
package pipeline

import "gitlab.com/ubiqsecurity/ubiq-go/v2/structured"

// Operation defines a single step in the encryption/decryption pipeline.
// Each operation transforms the CurrentValue in the context and returns the result.
type Operation interface {
	// Invoke executes the operation and returns the transformed value.
	// The context's CurrentValue should be updated by the caller after each operation.
	Invoke(ctx *OperationContext) (string, error)
}

// OperationContext carries state through the pipeline.
// It is created fresh for each encryption/decryption call and should not be reused.
type OperationContext struct {
	// Dataset holds the configuration for the current dataset
	Dataset *DatasetInfo

	// KeyNumber is the encryption key number.
	// For encryption: set by EncryptOperation, used by EncodeKeyNumberOperation
	// For decryption: set by DecodeKeyNumberOperation, used by DecryptOperation
	KeyNumber *int

	// OriginalValue is the initial input (immutable, for reference)
	OriginalValue string

	// CurrentValue is the value being transformed through the pipeline
	CurrentValue string

	// IsEncrypt indicates the direction: true = encryption, false = decryption
	IsEncrypt bool

	// Tweak is the optional user-supplied tweak for FF1
	Tweak []byte

	// Data is a shared dictionary for cross-operation communication.
	// Keys: "PassthroughTemplate", "Prefix", "Suffix"
	Data map[string]string
}

// DatasetInfo holds the dataset configuration needed by pipeline operations.
// This is a pipeline-specific view of the dataset, populated from the API response.
type DatasetInfo struct {
	Name                  string
	Algorithm             string
	InputCharacterSet     string
	OutputCharacterSet    string
	PassthroughCharacters string
	InputLengthMin        int
	InputLengthMax        int
	NumEncodingBits       int
	Tweak                 string // Base64-encoded default tweak
	TweakLengthMin        int
	TweakLengthMax        int

	// New fields for extended data type support
	InputPadCharacter string          // Character used for left-padding
	InputEncoding     string          // "base32", "base64", or "" for none
	DataType          string          // "string", "integer", "date", "datetime"
	DataTypeConfig    *DataTypeConfig // Additional config for non-string types

	// PassthroughRules defines prefix/suffix/passthrough handling
	PassthroughRules []PassthroughRule

	// Computed alphabets (set once when dataset is loaded)
	InputAlphabet       *structured.Alphabet
	OutputAlphabet      *structured.Alphabet
	PassthroughAlphabet *structured.Alphabet
}

// DataTypeConfig holds configuration for non-string data types.
type DataTypeConfig struct {
	Size             int64  // Bit size (32, 64)
	MinInputIntValue int64  // Minimum allowed integer value
	MaxInputIntValue int64  // Maximum allowed integer value
	Epoch            string // ISO8601 epoch for date/datetime (e.g., "1970-01-01T00:00:00Z")
	MinInputDate     string // Minimum allowed date (ISO8601)
	MaxInputDate     string // Maximum allowed date (ISO8601)
}

// PassthroughRule defines how to handle portions of input that bypass encryption.
type PassthroughRule struct {
	Type     string // "passthrough", "prefix", "suffix"
	Value    any    // Characters (string) for passthrough, length (int) for prefix/suffix
	Priority int    // Processing order (lower = earlier)
}

// NewOperationContext creates a new context for a pipeline invocation.
func NewOperationContext(dataset *DatasetInfo, value string, isEncrypt bool, tweak []byte) *OperationContext {
	return &OperationContext{
		Dataset:       dataset,
		OriginalValue: value,
		CurrentValue:  value,
		IsEncrypt:     isEncrypt,
		Tweak:         tweak,
		Data:          make(map[string]string),
	}
}
