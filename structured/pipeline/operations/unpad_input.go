package operations

import (
	"strings"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// UnpadInputOperation removes left-padding that was added by PadInputOperation.
// It strips all leading occurrences of the dataset's InputPadCharacter,
// matching the .NET TrimStart approach.
type UnpadInputOperation struct {
	padChar rune
}

// NewUnpadInputOperation creates a new unpad input operation.
func NewUnpadInputOperation(padChar rune) *UnpadInputOperation {
	return &UnpadInputOperation{padChar: padChar}
}

// Invoke removes leading pad characters from the current value.
func (op *UnpadInputOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	return strings.TrimLeft(ctx.CurrentValue, string(op.padChar)), nil
}
