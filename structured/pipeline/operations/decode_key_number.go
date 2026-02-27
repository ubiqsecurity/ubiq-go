package operations

import (
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// DecodeKeyNumberOperation extracts the key number from the first character.
// This is used during decryption to determine which key was used for encryption.
type DecodeKeyNumberOperation struct{}

// NewDecodeKeyNumberOperation creates a new key number decoding operation.
func NewDecodeKeyNumberOperation() *DecodeKeyNumberOperation {
	return &DecodeKeyNumberOperation{}
}

// Invoke extracts the key number from the first character and restores the original char.
// The key number is stored in ctx.KeyNumber for use by the decrypt operation.
// Even when NumEncodingBits is 0, the decoding still extracts the key number.
func (op *DecodeKeyNumberOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	ds := ctx.Dataset

	runes := []rune(ctx.CurrentValue)
	if len(runes) == 0 {
		return ctx.CurrentValue, nil
	}

	// Get encoded value from first character
	encodedIdx := ds.OutputAlphabet.PosOf(runes[0])
	if encodedIdx < 0 {
		return ctx.CurrentValue, nil
	}

	// Extract key number: keyNumber = encodedIdx >> numEncodingBits
	// When NumEncodingBits is 0, this becomes: keyNumber = encodedIdx
	keyNumber := encodedIdx >> ds.NumEncodingBits
	ctx.KeyNumber = &keyNumber

	// Recover original first character: originalIdx = encodedIdx - (keyNumber << numEncodingBits)
	// When NumEncodingBits is 0, this becomes: originalIdx = encodedIdx - keyNumber
	originalIdx := encodedIdx - (keyNumber << ds.NumEncodingBits)
	runes[0] = ds.OutputAlphabet.ValAt(originalIdx)

	return string(runes), nil
}
