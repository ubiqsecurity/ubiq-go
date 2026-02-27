package operations

import (
	"strconv"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// PadInputOperation pads the input to a minimum length using a specified character.
// The original length is stored for later unpadding.
type PadInputOperation struct {
	minLength int
	padChar   rune
}

// NewPadInputOperation creates a new pad input operation.
// minLength specifies the minimum required length.
// padChar is the character used for padding (prepended to the left).
func NewPadInputOperation(minLength int, padChar rune) *PadInputOperation {
	return &PadInputOperation{
		minLength: minLength,
		padChar:   padChar,
	}
}

// Invoke pads the current value if shorter than minLength.
// Stores the original length in ctx.Data["OriginalLength"] for unpadding.
func (op *PadInputOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	runes := []rune(ctx.CurrentValue)
	currentLen := len(runes)

	// Store original length for unpadding
	ctx.Data["OriginalLength"] = strconv.Itoa(currentLen)

	if currentLen >= op.minLength {
		return ctx.CurrentValue, nil
	}

	// Calculate padding needed
	padCount := op.minLength - currentLen

	// Create padded string (left padding)
	padded := make([]rune, op.minLength)
	for i := 0; i < padCount; i++ {
		padded[i] = op.padChar
	}
	copy(padded[padCount:], runes)

	return string(padded), nil
}
