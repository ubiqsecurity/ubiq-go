package operations

import (
	"strings"
	"testing"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

func mustAlphabet(t *testing.T, s string) *structured.Alphabet {
	t.Helper()
	a, err := structured.NewAlphabet(s)
	if err != nil {
		t.Fatal(err)
	}
	return &a
}

func TestValidateCharset(t *testing.T) {
	in := mustAlphabet(t, "abcdefghij")
	out := mustAlphabet(t, "0123456789")
	ds := &pipeline.DatasetInfo{InputAlphabet: in, OutputAlphabet: out}

	cases := []struct {
		name      string
		isEncrypt bool
		value     string
		wantErr   bool
	}{
		{"encrypt valid", true, "abcde", false},
		{"encrypt invalid", true, "ab!de", true},
		{"encrypt out-alphabet char is invalid for input", true, "01234", true},
		{"decrypt valid", false, "01234", false},
		{"decrypt invalid", false, "012!4", true},
	}

	op := NewValidateCharsetOperation()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := pipeline.NewOperationContext(ds, tc.value, tc.isEncrypt, nil)
			out, err := op.Invoke(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "invalid input string character(s)") {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out != tc.value {
				t.Fatalf("value should pass through unchanged: got %q want %q", out, tc.value)
			}
		})
	}
}

// TestValidateCharset_NilAlphabet ensures a missing alphabet is a no-op rather
// than a nil dereference.
func TestValidateCharset_NilAlphabet(t *testing.T) {
	ds := &pipeline.DatasetInfo{}
	ctx := pipeline.NewOperationContext(ds, "anything", true, nil)
	if _, err := NewValidateCharsetOperation().Invoke(ctx); err != nil {
		t.Fatalf("nil alphabet should be a no-op, got: %v", err)
	}
}
