package ubiq

import (
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline"
	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured/pipeline/exec"
)

// toPipelineDatasetInfo converts internal datasetInfo to pipeline.DatasetInfo
func toPipelineDatasetInfo(ds datasetInfo) *pipeline.DatasetInfo {
	info := &pipeline.DatasetInfo{
		Name:                  ds.Name,
		Algorithm:             ds.Algorithm,
		InputCharacterSet:     ds.InputCharacterSet,
		OutputCharacterSet:    ds.OutputCharacterSet,
		PassthroughCharacters: ds.PassthroughCharacterSet,
		InputLengthMin:        ds.InputLengthMin,
		InputLengthMax:        ds.InputLengthMax,
		NumEncodingBits:       ds.NumEncodingBits,
		Tweak:                 ds.Tweak,
		TweakLengthMin:        ds.TweakLengthMin,
		TweakLengthMax:        ds.TweakLengthMax,
		InputAlphabet:         &ds.InputAlphabet,
		OutputAlphabet:        &ds.OutputAlphabet,
		PassthroughAlphabet:   &ds.PassthroughAlphabet,
	}

	// Convert passthrough rules
	if len(ds.PassthroughRules) > 0 {
		info.PassthroughRules = make([]pipeline.PassthroughRule, len(ds.PassthroughRules))
		for i, rule := range ds.PassthroughRules {
			info.PassthroughRules[i] = pipeline.PassthroughRule{
				Type:     rule.Type,
				Value:    rule.Value,
				Priority: rule.Priority,
			}
		}
	}

	return info
}

// toPipelineAlgorithm wraps structuredAlgorithm to implement exec.FF1Algorithm
type pipelineAlgorithmAdapter struct {
	algo structuredAlgorithm
}

func (a *pipelineAlgorithmAdapter) EncryptRunes(input []rune, tweak []byte) ([]rune, error) {
	return a.algo.EncryptRunes(input, tweak)
}

func (a *pipelineAlgorithmAdapter) DecryptRunes(input []rune, tweak []byte) ([]rune, error) {
	return a.algo.DecryptRunes(input, tweak)
}

func wrapAlgorithm(algo structuredAlgorithm) exec.FF1Algorithm {
	return &pipelineAlgorithmAdapter{algo: algo}
}
