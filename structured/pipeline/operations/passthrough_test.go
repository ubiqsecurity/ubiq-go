package operations

import (
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

func TestTrimPassthroughOperation_SSN(t *testing.T) {
	digits, _ := structured.NewAlphabet("0123456789")
	dashes, _ := structured.NewAlphabet("-")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			InputAlphabet:       &digits,
			OutputAlphabet:      &digits,
			PassthroughAlphabet: &dashes,
		},
		CurrentValue: "123-45-6789",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewTrimPassthroughOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should strip dashes
	if result != "123456789" {
		t.Errorf("expected '123456789', got '%s'", result)
	}

	// Should store template with dashes preserved
	template := ctx.Data["PassthroughTemplate"]
	if template != "000-00-0000" {
		t.Errorf("expected template '000-00-0000', got '%s'", template)
	}
}

func TestTrimPassthroughOperation_NoPassthrough(t *testing.T) {
	digits, _ := structured.NewAlphabet("0123456789")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			InputAlphabet:       &digits,
			OutputAlphabet:      &digits,
			PassthroughAlphabet: nil, // No passthrough
		},
		CurrentValue: "123456789",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewTrimPassthroughOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should pass through unchanged
	if result != "123456789" {
		t.Errorf("expected '123456789', got '%s'", result)
	}
}

func TestExpandPassthroughOperation_SSN(t *testing.T) {
	digits, _ := structured.NewAlphabet("0123456789")
	dashes, _ := structured.NewAlphabet("-")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			InputAlphabet:       &digits,
			OutputAlphabet:      &digits,
			PassthroughAlphabet: &dashes,
		},
		CurrentValue: "987654321", // Encrypted digits
		IsEncrypt:    true,
		Data: map[string]string{
			"PassthroughTemplate": "000-00-0000",
		},
	}

	op := NewExpandPassthroughOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should restore dashes
	if result != "987-65-4321" {
		t.Errorf("expected '987-65-4321', got '%s'", result)
	}
}

func TestExpandPassthroughOperation_NoTemplate(t *testing.T) {
	digits, _ := structured.NewAlphabet("0123456789")

	ctx := &pipeline.OperationContext{
		Dataset: &pipeline.DatasetInfo{
			InputAlphabet:  &digits,
			OutputAlphabet: &digits,
		},
		CurrentValue: "123456789",
		IsEncrypt:    true,
		Data:         make(map[string]string), // No template
	}

	op := NewExpandPassthroughOperation()
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should pass through unchanged
	if result != "123456789" {
		t.Errorf("expected '123456789', got '%s'", result)
	}
}

func TestTrimExpandPassthrough_Roundtrip(t *testing.T) {
	alpha, _ := structured.NewAlphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	passthrough, _ := structured.NewAlphabet("-/. ")

	testCases := []struct {
		name  string
		input string
	}{
		{"ssn", "123-45-6789"},
		{"phone", "555-123-4567"},
		{"date_slashes", "01/15/2026"},
		{"mixed", "ABC-123/DEF.456 XYZ"},
		{"no_passthrough", "ABCDEFG123"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Trim
			trimCtx := &pipeline.OperationContext{
				Dataset: &pipeline.DatasetInfo{
					InputAlphabet:       &alpha,
					OutputAlphabet:      &alpha,
					PassthroughAlphabet: &passthrough,
				},
				CurrentValue: tc.input,
				IsEncrypt:    true,
				Data:         make(map[string]string),
			}

			trimOp := NewTrimPassthroughOperation()
			trimmed, err := trimOp.Invoke(trimCtx)
			if err != nil {
				t.Fatalf("trim error: %v", err)
			}

			// Simulate encryption (just reverse for testing)
			encrypted := reverseString(trimmed)

			// Expand
			expandCtx := &pipeline.OperationContext{
				Dataset: &pipeline.DatasetInfo{
					InputAlphabet:       &alpha,
					OutputAlphabet:      &alpha,
					PassthroughAlphabet: &passthrough,
				},
				CurrentValue: encrypted,
				IsEncrypt:    true,
				Data: map[string]string{
					"PassthroughTemplate": trimCtx.Data["PassthroughTemplate"],
				},
			}

			expandOp := NewExpandPassthroughOperation()
			expanded, err := expandOp.Invoke(expandCtx)
			if err != nil {
				t.Fatalf("expand error: %v", err)
			}

			// Verify passthrough characters are in correct positions
			inputRunes := []rune(tc.input)
			expandedRunes := []rune(expanded)

			if len(inputRunes) != len(expandedRunes) {
				t.Errorf("length mismatch: input %d, expanded %d", len(inputRunes), len(expandedRunes))
				return
			}

			for i, ir := range inputRunes {
				if passthrough.PosOf(ir) >= 0 {
					// Passthrough char should be preserved
					if expandedRunes[i] != ir {
						t.Errorf("position %d: expected passthrough '%c', got '%c'", i, ir, expandedRunes[i])
					}
				}
			}
		})
	}
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
