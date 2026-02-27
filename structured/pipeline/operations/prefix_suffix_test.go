package operations

import (
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

func TestTrimPrefixOperation(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "ABC123456",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewTrimPrefixOperation(3)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "123456" {
		t.Errorf("expected '123456', got '%s'", result)
	}

	if ctx.Data["Prefix"] != "ABC" {
		t.Errorf("expected prefix 'ABC', got '%s'", ctx.Data["Prefix"])
	}
}

func TestTrimPrefixOperation_ZeroLength(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "ABC123456",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewTrimPrefixOperation(0)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "ABC123456" {
		t.Errorf("expected 'ABC123456', got '%s'", result)
	}
}

func TestExpandPrefixOperation(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "654321",
		IsEncrypt:    true,
		Data: map[string]string{
			"Prefix": "ABC",
		},
	}

	op := NewExpandPrefixOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "ABC654321" {
		t.Errorf("expected 'ABC654321', got '%s'", result)
	}
}

func TestExpandPrefixOperation_NoPrefix(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "123456",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewExpandPrefixOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "123456" {
		t.Errorf("expected '123456', got '%s'", result)
	}
}

func TestTrimSuffixOperation(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "123456XYZ",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewTrimSuffixOperation(3)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "123456" {
		t.Errorf("expected '123456', got '%s'", result)
	}

	if ctx.Data["Suffix"] != "XYZ" {
		t.Errorf("expected suffix 'XYZ', got '%s'", ctx.Data["Suffix"])
	}
}

func TestTrimSuffixOperation_ZeroLength(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "123456XYZ",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewTrimSuffixOperation(0)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "123456XYZ" {
		t.Errorf("expected '123456XYZ', got '%s'", result)
	}
}

func TestExpandSuffixOperation(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "654321",
		IsEncrypt:    true,
		Data: map[string]string{
			"Suffix": "XYZ",
		},
	}

	op := NewExpandSuffixOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "654321XYZ" {
		t.Errorf("expected '654321XYZ', got '%s'", result)
	}
}

func TestPrefixSuffix_Roundtrip(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		prefixLen    int
		suffixLen    int
	}{
		{"prefix_only", "ABC123456", 3, 0},
		{"suffix_only", "123456XYZ", 0, 3},
		{"both", "ABC123XYZ", 3, 3},
		{"no_trim", "123456789", 0, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: tc.input,
				IsEncrypt:    true,
				Data:         make(map[string]string),
			}

			// Trim prefix
			trimPrefixOp := NewTrimPrefixOperation(tc.prefixLen)
			result, _ := trimPrefixOp.Invoke(ctx)
			ctx.CurrentValue = result

			// Trim suffix
			trimSuffixOp := NewTrimSuffixOperation(tc.suffixLen)
			result, _ = trimSuffixOp.Invoke(ctx)
			ctx.CurrentValue = result

			// Simulate encryption (reverse)
			ctx.CurrentValue = reverseString(ctx.CurrentValue)

			// Expand suffix
			expandSuffixOp := NewExpandSuffixOperation()
			result, _ = expandSuffixOp.Invoke(ctx)
			ctx.CurrentValue = result

			// Expand prefix
			expandPrefixOp := NewExpandPrefixOperation()
			result, _ = expandPrefixOp.Invoke(ctx)

			// Verify prefix and suffix are unchanged
			inputRunes := []rune(tc.input)
			resultRunes := []rune(result)

			if len(inputRunes) != len(resultRunes) {
				t.Errorf("length mismatch: expected %d, got %d", len(inputRunes), len(resultRunes))
				return
			}

			// Check prefix preserved
			for i := 0; i < tc.prefixLen; i++ {
				if inputRunes[i] != resultRunes[i] {
					t.Errorf("prefix char %d: expected '%c', got '%c'", i, inputRunes[i], resultRunes[i])
				}
			}

			// Check suffix preserved
			for i := 0; i < tc.suffixLen; i++ {
				inputIdx := len(inputRunes) - tc.suffixLen + i
				resultIdx := len(resultRunes) - tc.suffixLen + i
				if inputRunes[inputIdx] != resultRunes[resultIdx] {
					t.Errorf("suffix char %d: expected '%c', got '%c'", i, inputRunes[inputIdx], resultRunes[resultIdx])
				}
			}
		})
	}
}
