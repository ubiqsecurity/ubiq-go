package operations

import (
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// EncodeKeyNumberOperation embeds the key number into the first character.
// This allows the decryption process to determine which key was used.
type EncodeKeyNumberOperation struct{}

// NewEncodeKeyNumberOperation creates a new key number encoding operation.
func NewEncodeKeyNumberOperation() *EncodeKeyNumberOperation {
	return &EncodeKeyNumberOperation{}
}

// Invoke encodes the key number into the first character using bit shifting.
// The key number is shifted left by NumEncodingBits and added to the first char's index.
// Even when NumEncodingBits is 0, the encoding still happens (just adds the key number).
func (op *EncodeKeyNumberOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	ds := ctx.Dataset

	// Skip if no key number
	if ctx.KeyNumber == nil {
		return ctx.CurrentValue, nil
	}

	runes := []rune(ctx.CurrentValue)
	if len(runes) == 0 {
		return ctx.CurrentValue, nil
	}

	// Get index of first character in output alphabet
	firstIdx := ds.OutputAlphabet.PosOf(runes[0])
	if firstIdx < 0 {
		return ctx.CurrentValue, nil
	}

	// Encode key number: newIdx = firstIdx + (keyNumber << numEncodingBits)
	// When NumEncodingBits is 0, this becomes: newIdx = firstIdx + keyNumber
	encodedIdx := firstIdx + (*ctx.KeyNumber << ds.NumEncodingBits)

	runes[0] = ds.OutputAlphabet.ValAt(encodedIdx)

	return string(runes), nil
}
