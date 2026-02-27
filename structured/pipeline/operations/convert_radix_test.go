package operations

import (
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

func TestConvertRadixOperation_SameAlphabet(t *testing.T) {
	// When input and output alphabets are the same, value should be unchanged
	alpha, _ := structured.NewAlphabet("0123456789")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			InputAlphabet:  &alpha,
			OutputAlphabet: &alpha,
		},
		CurrentValue: "123456789",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewConvertRadixOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "123456789" {
		t.Errorf("expected '123456789', got '%s'", result)
	}
}

func TestConvertRadixOperation_DifferentAlphabets(t *testing.T) {
	// Convert from decimal to hex-like alphabet
	decimal, _ := structured.NewAlphabet("0123456789")
	hexAlpha, _ := structured.NewAlphabet("0123456789ABCDEF")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			InputAlphabet:  &decimal,
			OutputAlphabet: &hexAlpha,
		},
		CurrentValue: "255", // decimal 255
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewConvertRadixOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 255 in decimal = 0FF in hex, but with length preservation (3 chars)
	if result != "0FF" {
		t.Errorf("expected '0FF', got '%s'", result)
	}
}

func TestConvertRadixOperation_Decrypt(t *testing.T) {
	// Decryption should reverse the alphabets
	decimal, _ := structured.NewAlphabet("0123456789")
	hexAlpha, _ := structured.NewAlphabet("0123456789ABCDEF")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			InputAlphabet:  &decimal,
			OutputAlphabet: &hexAlpha,
		},
		CurrentValue: "0FF", // hex 0FF = 255 decimal
		IsEncrypt:    false, // decryption: from output to input
		Data:         make(map[string]string),
	}

	op := NewConvertRadixOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "255" {
		t.Errorf("expected '255', got '%s'", result)
	}
}
