package operations

import (
	"strings"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// TrimPassthroughOperation removes passthrough characters from input and
// creates a template for later restoration. Passthrough characters are
// characters that should remain unencrypted at their original positions
// (e.g., dashes in SSN: "123-45-6789").
type TrimPassthroughOperation struct{}

// NewTrimPassthroughOperation creates a new trim passthrough operation.
func NewTrimPassthroughOperation() *TrimPassthroughOperation {
	return &TrimPassthroughOperation{}
}

// Invoke removes passthrough characters and stores a template in ctx.Data["PassthroughTemplate"].
// The template uses the actual passthrough characters in their positions and a placeholder
// character for positions that will contain encrypted data.
func (op *TrimPassthroughOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	ds := ctx.Dataset

	// Skip if no passthrough characters configured
	if ds.PassthroughAlphabet == nil || ds.PassthroughAlphabet.Len() == 0 {
		return ctx.CurrentValue, nil
	}

	// Choose placeholder based on direction:
	// - Encryption: use first char from output alphabet
	// - Decryption: use first char from input alphabet
	var placeholder rune
	if ctx.IsEncrypt {
		placeholder = ds.OutputAlphabet.ValAt(0)
	} else {
		placeholder = ds.InputAlphabet.ValAt(0)
	}

	var result strings.Builder
	var template strings.Builder

	for _, r := range ctx.CurrentValue {
		if ds.PassthroughAlphabet.PosOf(r) >= 0 {
			// Passthrough character - preserve in template
			template.WriteRune(r)
		} else {
			// Regular character - add to result, placeholder to template
			result.WriteRune(r)
			template.WriteRune(placeholder)
		}
	}

	// Store template for ExpandPassthroughOperation
	ctx.Data["PassthroughTemplate"] = template.String()

	return result.String(), nil
}
