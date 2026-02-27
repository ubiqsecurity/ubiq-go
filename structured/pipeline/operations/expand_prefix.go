package operations

import (
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
)

// ExpandPrefixOperation restores the prefix that was removed by TrimPrefixOperation.
type ExpandPrefixOperation struct{}

// NewExpandPrefixOperation creates a new expand prefix operation.
func NewExpandPrefixOperation() *ExpandPrefixOperation {
	return &ExpandPrefixOperation{}
}

// Invoke prepends the stored prefix to the current value.
func (op *ExpandPrefixOperation) Invoke(ctx *pipeline.OperationContext) (string, error) {
	prefix, ok := ctx.Data["Prefix"]
	if !ok || prefix == "" {
		return ctx.CurrentValue, nil
	}

	return prefix + ctx.CurrentValue, nil
}
