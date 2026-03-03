package operations

import (
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

func TestPadInputOperation(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "123",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewPadInputOperation(6, '0')
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "000123" {
		t.Errorf("expected '000123', got '%s'", result)
	}

	if ctx.Data["OriginalLength"] != "3" {
		t.Errorf("expected OriginalLength '3', got '%s'", ctx.Data["OriginalLength"])
	}
}

func TestPadInputOperation_NoChange(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "123456",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewPadInputOperation(6, '0')
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "123456" {
		t.Errorf("expected '123456', got '%s'", result)
	}
}

func TestPadInputOperation_LongerThanMin(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "12345678",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewPadInputOperation(6, '0')
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "12345678" {
		t.Errorf("expected '12345678', got '%s'", result)
	}
}

func TestUnpadInputOperation(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "000123",
		IsEncrypt:    false,
		Data:         make(map[string]string),
	}

	op := NewUnpadInputOperation('0')
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "123" {
		t.Errorf("expected '123', got '%s'", result)
	}
}

func TestUnpadInputOperation_NoPadding(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "123456",
		IsEncrypt:    false,
		Data:         make(map[string]string),
	}

	op := NewUnpadInputOperation('0')
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "123456" {
		t.Errorf("expected '123456', got '%s'", result)
	}
}

func TestPadUnpad_Roundtrip(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		minLength int
		padChar   rune
	}{
		{"short_numeric", "123", 6, '0'},
		{"already_min", "123456", 6, '0'},
		{"longer_than_min", "12345678", 6, '0'},
		{"single_char", "5", 4, '0'},
		{"empty_after_pad", "", 3, 'X'},
		{"unicode", "αβγ", 6, '0'},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Pad
			padCtx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: tc.input,
				IsEncrypt:    true,
				Data:         make(map[string]string),
			}

			padOp := NewPadInputOperation(tc.minLength, tc.padChar)
			padded, err := padOp.Invoke(padCtx)
			if err != nil {
				t.Fatalf("pad error: %v", err)
			}

			// Verify minimum length
			if len([]rune(padded)) < tc.minLength && tc.input != "" {
				t.Errorf("padded length %d < minLength %d", len([]rune(padded)), tc.minLength)
			}

			// Unpad
			unpadCtx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: padded,
				IsEncrypt:    false,
				Data:         padCtx.Data, // Copy stored OriginalLength
			}

			unpadOp := NewUnpadInputOperation(tc.padChar)
			unpadded, err := unpadOp.Invoke(unpadCtx)
			if err != nil {
				t.Fatalf("unpad error: %v", err)
			}

			if unpadded != tc.input {
				t.Errorf("roundtrip failed: expected '%s', got '%s'", tc.input, unpadded)
			}
		})
	}
}

func TestPadInputOperation_DifferentPadChars(t *testing.T) {
	testCases := []struct {
		padChar  rune
		expected string
	}{
		{'0', "00123"},
		{' ', "  123"},
		{'X', "XX123"},
		{'_', "__123"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.padChar), func(t *testing.T) {
			ctx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: "123",
				IsEncrypt:    true,
				Data:         make(map[string]string),
			}

			op := NewPadInputOperation(5, tc.padChar)
			result, err := op.Invoke(ctx)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}
