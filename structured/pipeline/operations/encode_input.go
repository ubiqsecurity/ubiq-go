package operations

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// EncodingType represents the type of encoding to apply.
type EncodingType int

const (
	EncodingNone EncodingType = iota
	EncodingBase32
	EncodingBase64
)

// EncodeInputOperation encodes the current value using the specified encoding.
// This is used during decryption to convert plaintext back to encoded form.
type EncodeInputOperation struct {
	encoding EncodingType
}

// NewEncodeInputOperation creates a new encode input operation.
func NewEncodeInputOperation(encoding EncodingType) *EncodeInputOperation {
	return &EncodeInputOperation{encoding: encoding}
}

// Invoke encodes the current value using the configured encoding.
func (op *EncodeInputOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	if op.encoding == EncodingNone {
		return ctx.CurrentValue, nil
	}

	data := []byte(ctx.CurrentValue)

	switch op.encoding {
	case EncodingBase32:
		return base32.StdEncoding.EncodeToString(data), nil

	case EncodingBase64:
		return base64.StdEncoding.EncodeToString(data), nil

	default:
		return "", fmt.Errorf("unsupported encoding type: %d", op.encoding)
	}
}
