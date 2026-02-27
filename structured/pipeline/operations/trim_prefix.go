package operations

import (
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// TrimPrefixOperation removes a fixed-length prefix from the input and
// stores it for later restoration. The prefix bypasses encryption.
type TrimPrefixOperation struct {
	length int
}

// NewTrimPrefixOperation creates a new trim prefix operation.
// The length parameter specifies how many characters to trim from the start.
func NewTrimPrefixOperation(length int) *TrimPrefixOperation {
	return &TrimPrefixOperation{length: length}
}

// Invoke removes the prefix and stores it in ctx.Data["Prefix"].
func (op *TrimPrefixOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	if op.length <= 0 {
		return ctx.CurrentValue, nil
	}

	runes := []rune(ctx.CurrentValue)
	if len(runes) <= op.length {
		return ctx.CurrentValue, nil
	}

	// Store prefix for ExpandPrefixOperation
	ctx.Data["Prefix"] = string(runes[:op.length])

	// Return remainder
	return string(runes[op.length:]), nil
}
