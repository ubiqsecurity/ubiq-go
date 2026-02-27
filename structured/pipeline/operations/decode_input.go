package operations

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// DecodeInputOperation decodes the current value from the specified encoding.
// This is used during encryption to decode base32/base64 input before processing.
type DecodeInputOperation struct {
	encoding EncodingType
}

// NewDecodeInputOperation creates a new decode input operation.
func NewDecodeInputOperation(encoding EncodingType) *DecodeInputOperation {
	return &DecodeInputOperation{encoding: encoding}
}

// Invoke decodes the current value using the configured encoding.
func (op *DecodeInputOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	if op.encoding == EncodingNone {
		return ctx.CurrentValue, nil
	}

	input := ctx.CurrentValue

	switch op.encoding {
	case EncodingBase32:
		// Add padding if needed for proper decoding
		input = addBase32Padding(input)
		decoded, err := base32.StdEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("base32 decode error: %w", err)
		}
		return string(decoded), nil

	case EncodingBase64:
		// Add padding if needed for proper decoding
		input = addBase64Padding(input)
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("base64 decode error: %w", err)
		}
		return string(decoded), nil

	default:
		return "", fmt.Errorf("unsupported encoding type: %d", op.encoding)
	}
}

// addBase32Padding adds required padding to a base32 string.
// Base32 requires input length to be a multiple of 8.
func addBase32Padding(s string) string {
	padLen := (8 - len(s)%8) % 8
	for i := 0; i < padLen; i++ {
		s += "="
	}
	return s
}

// addBase64Padding adds required padding to a base64 string.
// Base64 requires input length to be a multiple of 4.
func addBase64Padding(s string) string {
	padLen := (4 - len(s)%4) % 4
	for i := 0; i < padLen; i++ {
		s += "="
	}
	return s
}
