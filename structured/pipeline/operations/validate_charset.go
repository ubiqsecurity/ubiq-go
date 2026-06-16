package operations

import (
	"errors"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// ValidateCharsetOperation verifies that every character in the current value
// belongs to the relevant character set before it reaches the radix conversion
// or FF1. Without this guard, an out-of-charset character produces a position of
// -1 from Alphabet.PosOf, which then indexes the default alphabet at -1 and
// panics ("index out of range [-1]"). This restores the validation that the
// pre-pipeline formatInput used to perform.
//
// For encryption the value is validated against the input alphabet; for
// decryption it is validated against the output alphabet. The operation must run
// after passthrough/prefix/suffix characters have been trimmed, since those are
// not part of the alphabet being checked.
type ValidateCharsetOperation struct{}

// NewValidateCharsetOperation creates a new charset validation operation.
func NewValidateCharsetOperation() *ValidateCharsetOperation {
	return &ValidateCharsetOperation{}
}

// Invoke returns an error if the current value contains a character that is not
// in the relevant alphabet, leaving the value unchanged otherwise.
func (op *ValidateCharsetOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	var alphabet *structured.Alphabet
	if ctx.IsEncrypt {
		alphabet = ctx.Dataset.InputAlphabet
	} else {
		alphabet = ctx.Dataset.OutputAlphabet
	}

	// If the alphabet is not configured there is nothing to validate against.
	if alphabet == nil {
		return ctx.CurrentValue, nil
	}

	for _, c := range ctx.CurrentValue {
		if alphabet.PosOf(c) == -1 {
			return "", errors.New("invalid input string character(s)")
		}
	}

	return ctx.CurrentValue, nil
}
