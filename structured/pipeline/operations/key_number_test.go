package operations

import (
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

func TestEncodeKeyNumberOperation(t *testing.T) {
	alpha, _ := structured.NewAlphabet("0123456789")
	keyNum := 2

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			OutputAlphabet:  &alpha,
			NumEncodingBits: 2, // 4 possible keys (0-3)
		},
		CurrentValue: "0123456789",
		KeyNumber:    &keyNum,
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewEncodeKeyNumberOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First char '0' (index 0) + (2 << 2) = 0 + 8 = '8'
	expected := "8123456789"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

func TestDecodeKeyNumberOperation(t *testing.T) {
	alpha, _ := structured.NewAlphabet("0123456789")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			OutputAlphabet:  &alpha,
			NumEncodingBits: 2,
		},
		CurrentValue: "8123456789", // '8' encodes key 2 with original char '0'
		IsEncrypt:    false,
		Data:         make(map[string]string),
	}

	op := NewDecodeKeyNumberOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should restore '0' and extract key number 2
	expected := "0123456789"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}

	if ctx.KeyNumber == nil || *ctx.KeyNumber != 2 {
		t.Errorf("expected key number 2, got %v", ctx.KeyNumber)
	}
}

func TestEncodeDecodeKeyNumber_Roundtrip(t *testing.T) {
	alpha, _ := structured.NewAlphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	testCases := []struct {
		name     string
		input    string
		keyNum   int
		encBits  int
	}{
		{"key0_2bits", "ABC123", 0, 2},
		{"key1_2bits", "ABC123", 1, 2},
		{"key2_2bits", "ABC123", 2, 2},
		{"key3_2bits", "ABC123", 3, 2},
		{"key1_3bits", "ABC123", 1, 3}, // key 1 with 3 bits: 'A'(0) + (1<<3) = 8 = 'I'
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyNum := tc.keyNum

			// Encode
			encCtx := &pipeline.OperationContext{
				Dataset: &pipeline.DatasetInfo{
					OutputAlphabet:  &alpha,
					NumEncodingBits: tc.encBits,
				},
				CurrentValue: tc.input,
				KeyNumber:    &keyNum,
				IsEncrypt:    true,
				Data:         make(map[string]string),
			}

			encOp := NewEncodeKeyNumberOperation()
			encoded, err := encOp.Invoke(encCtx)
			if err != nil {
				t.Fatalf("encode error: %v", err)
			}

			// Decode
			decCtx := &pipeline.OperationContext{
				Dataset: &pipeline.DatasetInfo{
					OutputAlphabet:  &alpha,
					NumEncodingBits: tc.encBits,
				},
				CurrentValue: encoded,
				IsEncrypt:    false,
				Data:         make(map[string]string),
			}

			decOp := NewDecodeKeyNumberOperation()
			decoded, err := decOp.Invoke(decCtx)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}

			// Verify roundtrip
			if decoded != tc.input {
				t.Errorf("roundtrip failed: expected '%s', got '%s'", tc.input, decoded)
			}
			if decCtx.KeyNumber == nil || *decCtx.KeyNumber != tc.keyNum {
				t.Errorf("key number mismatch: expected %d, got %v", tc.keyNum, decCtx.KeyNumber)
			}
		})
	}
}

func TestEncodeKeyNumber_NoEncodingBits(t *testing.T) {
	alpha, _ := structured.NewAlphabet("0123456789")
	keyNum := 2

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			OutputAlphabet:  &alpha,
			NumEncodingBits: 0, // No bit shifting, but still adds key number
		},
		CurrentValue: "123456",
		KeyNumber:    &keyNum,
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewEncodeKeyNumberOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// When NumEncodingBits == 0:
	// encodedIdx = firstIdx + (keyNumber << 0) = 1 + 2 = 3
	// First char changes from '1' to '3'
	if result != "323456" {
		t.Errorf("expected '323456', got '%s'", result)
	}
}
