package operations

import (
	"strconv"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// UnpadInputOperation removes padding that was added by PadInputOperation.
// It uses the stored original length to restore the value.
type UnpadInputOperation struct{}

// NewUnpadInputOperation creates a new unpad input operation.
func NewUnpadInputOperation() *UnpadInputOperation {
	return &UnpadInputOperation{}
}

// Invoke removes left padding based on the stored original length.
func (op *UnpadInputOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	origLenStr, ok := ctx.Data["OriginalLength"]
	if !ok || origLenStr == "" {
		// No padding was applied
		return ctx.CurrentValue, nil
	}

	origLen, err := strconv.Atoi(origLenStr)
	if err != nil {
		// Invalid stored length, return unchanged
		return ctx.CurrentValue, nil
	}

	runes := []rune(ctx.CurrentValue)
	currentLen := len(runes)

	if currentLen <= origLen {
		// Current value is already shorter or equal to original
		return ctx.CurrentValue, nil
	}

	// Remove left padding (take the rightmost origLen characters)
	return string(runes[currentLen-origLen:]), nil
}
