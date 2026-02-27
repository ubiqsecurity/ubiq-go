package operations

import (
	"math/big"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// ConvertRadixOperation converts between input and output character sets.
// For encryption: converts from InputAlphabet to OutputAlphabet
// For decryption: converts from OutputAlphabet to InputAlphabet
type ConvertRadixOperation struct{}

// NewConvertRadixOperation creates a new radix conversion operation.
func NewConvertRadixOperation() *ConvertRadixOperation {
	return &ConvertRadixOperation{}
}

// Invoke performs the radix conversion using big integer arithmetic.
func (op *ConvertRadixOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	ds := ctx.Dataset
	runes := []rune(ctx.CurrentValue)

	var fromAlphabet, toAlphabet *structured.Alphabet

	if ctx.IsEncrypt {
		fromAlphabet = ds.InputAlphabet
		toAlphabet = ds.OutputAlphabet
	} else {
		fromAlphabet = ds.OutputAlphabet
		toAlphabet = ds.InputAlphabet
	}

	// Convert via big.Int: runes -> bigint -> runes in target alphabet
	n := big.NewInt(0)
	n = structured.RunesToBigInt(n, fromAlphabet, runes)

	result, err := structured.BigIntToRunes(toAlphabet, n, len(runes))
	if err != nil {
		return "", err
	}

	return string(result), nil
}
