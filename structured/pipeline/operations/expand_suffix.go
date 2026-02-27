package operations

import (
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// ExpandSuffixOperation restores the suffix that was removed by TrimSuffixOperation.
type ExpandSuffixOperation struct{}

// NewExpandSuffixOperation creates a new expand suffix operation.
func NewExpandSuffixOperation() *ExpandSuffixOperation {
	return &ExpandSuffixOperation{}
}

// Invoke appends the stored suffix to the current value.
func (op *ExpandSuffixOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	suffix, ok := ctx.Data["Suffix"]
	if !ok || suffix == "" {
		return ctx.CurrentValue, nil
	}

	return ctx.CurrentValue + suffix, nil
}
