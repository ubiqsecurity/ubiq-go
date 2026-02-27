// Package exec provides pipeline execution for structured encryption.
package exec

import (
	"fmt"
	"sort"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline/operations"
)

// FF1Algorithm defines the interface for FF1 encryption/decryption.
type FF1Algorithm interface {
	EncryptRunes([]rune, []byte) ([]rune, error)
	DecryptRunes([]rune, []byte) ([]rune, error)
}

// Encrypt encrypts plaintext using the pipeline architecture.
func Encrypt(
	dataset *pipeline.DatasetInfo,
	plaintext string,
	tweak []byte,
	keyNumber int,
	algorithm FF1Algorithm,
) (string, error) {
	ctx := pipeline.NewOperationContext(dataset, plaintext, true, tweak)
	ctx.KeyNumber = &keyNumber

	// Pre-encryption: trim prefix, suffix, passthrough
	pre := buildPrePipeline(dataset)
	if _, err := pre.Invoke(ctx); err != nil {
		return "", fmt.Errorf("pre-encrypt failed: %w", err)
	}

	// Validate length
	inputLen := len([]rune(ctx.CurrentValue))
	if inputLen < dataset.InputLengthMin || inputLen > dataset.InputLengthMax {
		return "", fmt.Errorf("invalid input length (%d) min: %d max: %d",
			inputLen, dataset.InputLengthMin, dataset.InputLengthMax)
	}

	// FF1 encryption
	encrypted, err := algorithm.EncryptRunes([]rune(ctx.CurrentValue), ctx.Tweak)
	if err != nil {
		return "", fmt.Errorf("FF1 encryption failed: %w", err)
	}
	ctx.CurrentValue = string(encrypted)

	// Post-encryption: convert radix, encode key, expand passthrough/suffix/prefix
	post := buildPostEncryptPipeline(dataset)
	if _, err := post.Invoke(ctx); err != nil {
		return "", fmt.Errorf("post-encrypt failed: %w", err)
	}

	return ctx.CurrentValue, nil
}

// Decrypt decrypts ciphertext using the pipeline architecture.
func Decrypt(
	dataset *pipeline.DatasetInfo,
	ciphertext string,
	tweak []byte,
	algorithmFactory func(keyNumber int) (FF1Algorithm, error),
) (string, int, error) {
	ctx := pipeline.NewOperationContext(dataset, ciphertext, false, tweak)

	// Pre-decryption: trim prefix, suffix, passthrough, decode key, convert radix
	pre := buildPreDecryptPipeline(dataset)
	if _, err := pre.Invoke(ctx); err != nil {
		return "", 0, fmt.Errorf("pre-decrypt failed: %w", err)
	}

	if ctx.KeyNumber == nil {
		return "", 0, fmt.Errorf("key number not decoded")
	}
	keyNumber := *ctx.KeyNumber

	algorithm, err := algorithmFactory(keyNumber)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get algorithm: %w", err)
	}

	// FF1 decryption
	decrypted, err := algorithm.DecryptRunes([]rune(ctx.CurrentValue), ctx.Tweak)
	if err != nil {
		return "", 0, fmt.Errorf("FF1 decryption failed: %w", err)
	}
	ctx.CurrentValue = string(decrypted)

	// Post-decryption: expand passthrough/suffix/prefix
	post := buildPostDecryptPipeline(dataset)
	if _, err := post.Invoke(ctx); err != nil {
		return "", 0, fmt.Errorf("post-decrypt failed: %w", err)
	}

	return ctx.CurrentValue, keyNumber, nil
}

// ruleWithOperation pairs a rule with its corresponding operation for sorting.
type ruleWithOperation struct {
	priority  int
	ruleType  string
	operation pipeline.Operation
}

func buildPrePipeline(ds *pipeline.DatasetInfo) *pipeline.Pipeline {
	var ops []pipeline.Operation

	// If PassthroughRules is defined, use priority-based sorting
	if len(ds.PassthroughRules) > 0 {
		var ruleOps []ruleWithOperation

		for _, rule := range ds.PassthroughRules {
			var op pipeline.Operation

			switch rule.Type {
			case "prefix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewTrimPrefixOperation(length)
				}
			case "suffix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewTrimSuffixOperation(length)
				}
			case "passthrough":
				if ds.PassthroughCharacters != "" {
					op = operations.NewTrimPassthroughOperation()
				}
			}

			if op != nil {
				ruleOps = append(ruleOps, ruleWithOperation{
					priority:  rule.Priority,
					ruleType:  rule.Type,
					operation: op,
				})
			}
		}

		// Sort by ascending priority (like old formatInput)
		sort.Slice(ruleOps, func(i, j int) bool {
			return ruleOps[i].priority < ruleOps[j].priority
		})

		// Extract sorted operations
		for _, r := range ruleOps {
			ops = append(ops, r.operation)
		}
	} else {
		// Fallback: use fixed order for datasets without PassthroughRules
		if prefixLen := getPrefixLength(ds); prefixLen > 0 {
			ops = append(ops, operations.NewTrimPrefixOperation(prefixLen))
		}
		if suffixLen := getSuffixLength(ds); suffixLen > 0 {
			ops = append(ops, operations.NewTrimSuffixOperation(suffixLen))
		}
		if ds.PassthroughCharacters != "" {
			ops = append(ops, operations.NewTrimPassthroughOperation())
		}
	}

	return pipeline.NewPipeline(ops...)
}

func buildPostEncryptPipeline(ds *pipeline.DatasetInfo) *pipeline.Pipeline {
	var ops []pipeline.Operation

	// ConvertRadix and EncodeKeyNumber always happen first (not part of rules)
	if ds.InputCharacterSet != ds.OutputCharacterSet {
		ops = append(ops, operations.NewConvertRadixOperation())
	}
	// Always encode key number (even when NumEncodingBits == 0)
	ops = append(ops, operations.NewEncodeKeyNumberOperation())

	// If PassthroughRules is defined, use priority-based sorting
	if len(ds.PassthroughRules) > 0 {
		var ruleOps []ruleWithOperation

		for _, rule := range ds.PassthroughRules {
			var op pipeline.Operation

			switch rule.Type {
			case "passthrough":
				if ds.PassthroughCharacters != "" {
					op = operations.NewExpandPassthroughOperation()
				}
			case "suffix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewExpandSuffixOperation()
				}
			case "prefix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewExpandPrefixOperation()
				}
			}

			if op != nil {
				ruleOps = append(ruleOps, ruleWithOperation{
					priority:  rule.Priority,
					ruleType:  rule.Type,
					operation: op,
				})
			}
		}

		// Sort by descending priority (like old formatOutput)
		sort.Slice(ruleOps, func(i, j int) bool {
			return ruleOps[i].priority > ruleOps[j].priority
		})

		// Append sorted operations
		for _, r := range ruleOps {
			ops = append(ops, r.operation)
		}
	} else {
		// Fallback: use fixed order for datasets without PassthroughRules
		if ds.PassthroughCharacters != "" {
			ops = append(ops, operations.NewExpandPassthroughOperation())
		}
		if getSuffixLength(ds) > 0 {
			ops = append(ops, operations.NewExpandSuffixOperation())
		}
		if getPrefixLength(ds) > 0 {
			ops = append(ops, operations.NewExpandPrefixOperation())
		}
	}

	return pipeline.NewPipeline(ops...)
}

func buildPreDecryptPipeline(ds *pipeline.DatasetInfo) *pipeline.Pipeline {
	var ops []pipeline.Operation

	// If PassthroughRules is defined, use priority-based sorting
	if len(ds.PassthroughRules) > 0 {
		var ruleOps []ruleWithOperation

		for _, rule := range ds.PassthroughRules {
			var op pipeline.Operation

			switch rule.Type {
			case "prefix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewTrimPrefixOperation(length)
				}
			case "suffix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewTrimSuffixOperation(length)
				}
			case "passthrough":
				if ds.PassthroughCharacters != "" {
					op = operations.NewTrimPassthroughOperation()
				}
			}

			if op != nil {
				ruleOps = append(ruleOps, ruleWithOperation{
					priority:  rule.Priority,
					ruleType:  rule.Type,
					operation: op,
				})
			}
		}

		// Sort by ascending priority
		sort.Slice(ruleOps, func(i, j int) bool {
			return ruleOps[i].priority < ruleOps[j].priority
		})

		// Append sorted operations
		for _, r := range ruleOps {
			ops = append(ops, r.operation)
		}
	} else {
		// Fallback: use fixed order for datasets without PassthroughRules
		if prefixLen := getPrefixLength(ds); prefixLen > 0 {
			ops = append(ops, operations.NewTrimPrefixOperation(prefixLen))
		}
		if suffixLen := getSuffixLength(ds); suffixLen > 0 {
			ops = append(ops, operations.NewTrimSuffixOperation(suffixLen))
		}
		if ds.PassthroughCharacters != "" {
			ops = append(ops, operations.NewTrimPassthroughOperation())
		}
	}

	// DecodeKeyNumber and ConvertRadix always happen after trim operations
	ops = append(ops, operations.NewDecodeKeyNumberOperation())
	if ds.InputCharacterSet != ds.OutputCharacterSet {
		ops = append(ops, operations.NewConvertRadixOperation())
	}

	return pipeline.NewPipeline(ops...)
}

func buildPostDecryptPipeline(ds *pipeline.DatasetInfo) *pipeline.Pipeline {
	var ops []pipeline.Operation

	// If PassthroughRules is defined, use priority-based sorting
	if len(ds.PassthroughRules) > 0 {
		var ruleOps []ruleWithOperation

		for _, rule := range ds.PassthroughRules {
			var op pipeline.Operation

			switch rule.Type {
			case "passthrough":
				if ds.PassthroughCharacters != "" {
					op = operations.NewExpandPassthroughOperation()
				}
			case "suffix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewExpandSuffixOperation()
				}
			case "prefix":
				if length := extractIntValue(rule.Value); length > 0 {
					op = operations.NewExpandPrefixOperation()
				}
			}

			if op != nil {
				ruleOps = append(ruleOps, ruleWithOperation{
					priority:  rule.Priority,
					ruleType:  rule.Type,
					operation: op,
				})
			}
		}

		// Sort by descending priority (like old formatOutput)
		sort.Slice(ruleOps, func(i, j int) bool {
			return ruleOps[i].priority > ruleOps[j].priority
		})

		// Append sorted operations
		for _, r := range ruleOps {
			ops = append(ops, r.operation)
		}
	} else {
		// Fallback: use fixed order for datasets without PassthroughRules
		if ds.PassthroughCharacters != "" {
			ops = append(ops, operations.NewExpandPassthroughOperation())
		}
		if getSuffixLength(ds) > 0 {
			ops = append(ops, operations.NewExpandSuffixOperation())
		}
		if getPrefixLength(ds) > 0 {
			ops = append(ops, operations.NewExpandPrefixOperation())
		}
	}

	return pipeline.NewPipeline(ops...)
}

func getPrefixLength(ds *pipeline.DatasetInfo) int {
	for _, rule := range ds.PassthroughRules {
		if rule.Type == "prefix" {
			return extractIntValue(rule.Value)
		}
	}
	return 0
}

func getSuffixLength(ds *pipeline.DatasetInfo) int {
	for _, rule := range ds.PassthroughRules {
		if rule.Type == "suffix" {
			return extractIntValue(rule.Value)
		}
	}
	return 0
}

// extractIntValue converts rule.Value (interface{}) to int, handling both int and float64.
func extractIntValue(value any) int {
	if l, ok := value.(int); ok {
		return l
	}
	if l, ok := value.(float64); ok {
		return int(l)
	}
	return 0
}
