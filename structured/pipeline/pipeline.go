package pipeline

import "fmt"

// Pipeline executes a sequence of operations in order.
// Pipelines are safe for concurrent use if all operations are stateless.
type Pipeline struct {
	operations []Operation
}

// NewPipeline creates a new pipeline with the given operations.
func NewPipeline(ops ...Operation) *Pipeline {
	return &Pipeline{operations: ops}
}

// Invoke executes all operations in sequence, updating the context's
// CurrentValue after each operation. Returns the final transformed value.
func (p *Pipeline) Invoke(ctx *OperationContext) (string, error) {
	for i, op := range p.operations {
		result, err := op.Invoke(ctx)
		if err != nil {
			return "", fmt.Errorf("pipeline operation %d failed: %w", i, err)
		}
		ctx.CurrentValue = result
	}
	return ctx.CurrentValue, nil
}

// Prepend adds operations at the beginning of the pipeline.
// Used to add pre-processing operations (e.g., TrimPassthrough).
func (p *Pipeline) Prepend(ops ...Operation) {
	p.operations = append(ops, p.operations...)
}

// Append adds operations at the end of the pipeline.
// Used to add post-processing operations (e.g., ExpandPassthrough).
func (p *Pipeline) Append(ops ...Operation) {
	p.operations = append(p.operations, ops...)
}

// Len returns the number of operations in the pipeline.
func (p *Pipeline) Len() int {
	return len(p.operations)
}
