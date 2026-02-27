package operations

import (
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// TrimSuffixOperation removes a fixed-length suffix from the input and
// stores it for later restoration. The suffix bypasses encryption.
type TrimSuffixOperation struct {
	length int
}

// NewTrimSuffixOperation creates a new trim suffix operation.
// The length parameter specifies how many characters to trim from the end.
func NewTrimSuffixOperation(length int) *TrimSuffixOperation {
	return &TrimSuffixOperation{length: length}
}

// Invoke removes the suffix and stores it in ctx.Data["Suffix"].
func (op *TrimSuffixOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	if op.length <= 0 {
		return ctx.CurrentValue, nil
	}

	runes := []rune(ctx.CurrentValue)
	if len(runes) <= op.length {
		return ctx.CurrentValue, nil
	}

	splitPoint := len(runes) - op.length

	// Store suffix for ExpandSuffixOperation
	ctx.Data["Suffix"] = string(runes[splitPoint:])

	// Return beginning portion
	return string(runes[:splitPoint]), nil
}
