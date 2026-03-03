package operations

import (
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

func TestEncodeInputOperation_Base64(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "Hello",
		IsEncrypt:    false,
		Data:         make(map[string]string),
	}

	op := NewEncodeInputOperation(EncodingBase64)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// "Hello" in base64 is "SGVsbG8=" with standard padding
	if result != "SGVsbG8=" {
		t.Errorf("expected 'SGVsbG8=', got '%s'", result)
	}
}

func TestEncodeInputOperation_Base32(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "Hello",
		IsEncrypt:    false,
		Data:         make(map[string]string),
	}

	op := NewEncodeInputOperation(EncodingBase32)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// "Hello" in base32 is "JBSWY3DP" (5 bytes = 8 base32 chars, no padding needed)
	if result != "JBSWY3DP" {
		t.Errorf("expected 'JBSWY3DP', got '%s'", result)
	}
}

func TestEncodeInputOperation_None(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "unchanged",
		IsEncrypt:    false,
		Data:         make(map[string]string),
	}

	op := NewEncodeInputOperation(EncodingNone)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "unchanged" {
		t.Errorf("expected 'unchanged', got '%s'", result)
	}
}

func TestDecodeInputOperation_Base64(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "SGVsbG8", // "Hello" without padding
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewDecodeInputOperation(EncodingBase64)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "Hello" {
		t.Errorf("expected 'Hello', got '%s'", result)
	}
}

func TestDecodeInputOperation_Base64_WithPadding(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "SGVsbG8=", // "Hello" with padding
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewDecodeInputOperation(EncodingBase64)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "Hello" {
		t.Errorf("expected 'Hello', got '%s'", result)
	}
}

func TestDecodeInputOperation_Base32(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "JBSWY3DP", // "Hello" without padding
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewDecodeInputOperation(EncodingBase32)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "Hello" {
		t.Errorf("expected 'Hello', got '%s'", result)
	}
}

func TestDecodeInputOperation_None(t *testing.T) {
	ctx := &pipeline.OperationContext{
		Dataset:      &pipeline.DatasetInfo{},
		CurrentValue: "unchanged",
		IsEncrypt:    true,
		Data:         make(map[string]string),
	}

	op := NewDecodeInputOperation(EncodingNone)
	result, err := op.Invoke(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "unchanged" {
		t.Errorf("expected 'unchanged', got '%s'", result)
	}
}

func TestEncoding_Roundtrip_Base64(t *testing.T) {
	testCases := []string{
		"Hello",
		"Hello, World!",
		"12345",
		"Test String 123",
		"Special: @#$%",
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			// Encode
			encodeCtx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: tc,
				IsEncrypt:    false,
				Data:         make(map[string]string),
			}

			encodeOp := NewEncodeInputOperation(EncodingBase64)
			encoded, err := encodeOp.Invoke(encodeCtx)
			if err != nil {
				t.Fatalf("encode error: %v", err)
			}

			// Decode
			decodeCtx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: encoded,
				IsEncrypt:    true,
				Data:         make(map[string]string),
			}

			decodeOp := NewDecodeInputOperation(EncodingBase64)
			decoded, err := decodeOp.Invoke(decodeCtx)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}

			if decoded != tc {
				t.Errorf("roundtrip failed: expected '%s', got '%s'", tc, decoded)
			}
		})
	}
}

func TestEncoding_Roundtrip_Base32(t *testing.T) {
	testCases := []string{
		"Hello",
		"World",
		"12345",
		"Test!",
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			// Encode
			encodeCtx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: tc,
				IsEncrypt:    false,
				Data:         make(map[string]string),
			}

			encodeOp := NewEncodeInputOperation(EncodingBase32)
			encoded, err := encodeOp.Invoke(encodeCtx)
			if err != nil {
				t.Fatalf("encode error: %v", err)
			}

			// Decode
			decodeCtx := &pipeline.OperationContext{
				Dataset:      &pipeline.DatasetInfo{},
				CurrentValue: encoded,
				IsEncrypt:    true,
				Data:         make(map[string]string),
			}

			decodeOp := NewDecodeInputOperation(EncodingBase32)
			decoded, err := decodeOp.Invoke(decodeCtx)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}

			if decoded != tc {
				t.Errorf("roundtrip failed: expected '%s', got '%s'", tc, decoded)
			}
		})
	}
}

func TestAddBase64Padding(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"SGVsbG8", "SGVsbG8="},   // needs 1 pad
		{"SGVs", "SGVs"},          // no pad needed
		{"SGVsbA", "SGVsbA=="},    // needs 2 pads
		{"SGVsbG9X", "SGVsbG9X"}, // no pad needed
	}

	for _, tc := range testCases {
		result := addBase64Padding(tc.input)
		if result != tc.expected {
			t.Errorf("addBase64Padding(%s): expected '%s', got '%s'", tc.input, tc.expected, result)
		}
	}
}

func TestAddBase32Padding(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"JBSWY3DP", "JBSWY3DP"},           // no pad needed (len 8)
		{"JBSWY3D", "JBSWY3D="},            // needs 1 pad
		{"JBSWY3", "JBSWY3=="},             // needs 2 pads
		{"JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"}, // no pad needed (len 16)
	}

	for _, tc := range testCases {
		result := addBase32Padding(tc.input)
		if result != tc.expected {
			t.Errorf("addBase32Padding(%s): expected '%s', got '%s'", tc.input, tc.expected, result)
		}
	}
}
