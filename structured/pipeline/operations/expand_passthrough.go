package operations

import (
	"errors"
	"strings"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// ExpandPassthroughOperation restores passthrough characters to their original
// positions using the template created by TrimPassthroughOperation.
type ExpandPassthroughOperation struct{}

// NewExpandPassthroughOperation creates a new expand passthrough operation.
func NewExpandPassthroughOperation() *ExpandPassthroughOperation {
	return &ExpandPassthroughOperation{}
}

// Invoke merges encrypted data with the passthrough template.
// Passthrough positions in the template retain their original characters,
// placeholder positions are filled with encrypted characters.
func (op *ExpandPassthroughOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	template, ok := ctx.Data["PassthroughTemplate"]
	if !ok || template == "" {
		return ctx.CurrentValue, nil
	}

	ds := ctx.Dataset

	// Skip if no passthrough alphabet
	if ds.PassthroughAlphabet == nil || ds.PassthroughAlphabet.Len() == 0 {
		return ctx.CurrentValue, nil
	}

	valueRunes := []rune(ctx.CurrentValue)
	templateRunes := []rune(template)

	var result strings.Builder
	valueIdx := 0

	for _, tr := range templateRunes {
		if ds.PassthroughAlphabet.PosOf(tr) >= 0 {
			// Passthrough position - use template character
			result.WriteRune(tr)
		} else {
			// Encrypted data position - use next value character
			if valueIdx >= len(valueRunes) {
				return "", errors.New("mismatched format and output strings")
			}
			result.WriteRune(valueRunes[valueIdx])
			valueIdx++
		}
	}

	// Verify all encrypted characters were consumed
	if valueIdx != len(valueRunes) {
		return "", errors.New("mismatched format and output strings")
	}

	return result.String(), nil
}
