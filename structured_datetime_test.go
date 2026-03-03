package ubiq

import (
	"testing"
	"time"
)

func TestParseEpoch(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Time
		wantErr  bool
	}{
		{
			"rfc3339",
			"1970-01-01T00:00:00Z",
			time.Unix(0, 0).UTC(),
			false,
		},
		{
			"date_only",
			"1970-01-01",
			time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			false,
		},
		{
			"datetime_no_tz",
			"2000-01-01T12:00:00",
			time.Date(2000, 1, 1, 12, 0, 0, 0, time.UTC),
			false,
		},
		{
			"empty",
			"",
			time.Unix(0, 0).UTC(),
			false,
		},
		{
			"invalid",
			"not-a-date",
			time.Time{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseEpoch(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseEpoch(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseEpoch(%q) unexpected error: %v", tt.input, err)
				return
			}
			if !result.Equal(tt.expected) {
				t.Errorf("parseEpoch(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Time
		wantErr  bool
	}{
		{
			"rfc3339",
			"2024-06-15T10:30:00Z",
			time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
			false,
		},
		{
			"date_only",
			"2024-06-15",
			time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC),
			false,
		},
		{
			"datetime_no_tz",
			"2024-06-15T10:30:00",
			time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
			false,
		},
		{
			"empty",
			"",
			time.Time{},
			false,
		},
		{
			"invalid",
			"not-a-date",
			time.Time{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDate(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDate(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseDate(%q) unexpected error: %v", tt.input, err)
				return
			}
			if tt.input == "" {
				if !result.IsZero() {
					t.Errorf("parseDate(%q) = %v, want zero time", tt.input, result)
				}
				return
			}
			if !result.Equal(tt.expected) {
				t.Errorf("parseDate(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateDateTimeDataset(t *testing.T) {
	sC := &structuredContext{}

	tests := []struct {
		name    string
		dataset datasetInfo
		wantErr bool
	}{
		{
			"valid",
			datasetInfo{
				Name:           "test",
				DataType:       "datetime",
				DataTypeConfig: &dataTypeConfig{},
			},
			false,
		},
		{
			"wrong_type",
			datasetInfo{
				Name:           "test",
				DataType:       "string",
				DataTypeConfig: &dataTypeConfig{},
			},
			true,
		},
		{
			"missing_config",
			datasetInfo{
				Name:     "test",
				DataType: "datetime",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sC.validateDateTimeDataset(tt.dataset)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateDateDataset(t *testing.T) {
	sC := &structuredContext{}

	tests := []struct {
		name    string
		dataset datasetInfo
		wantErr bool
	}{
		{
			"valid",
			datasetInfo{
				Name:           "test",
				DataType:       "date",
				DataTypeConfig: &dataTypeConfig{},
			},
			false,
		},
		{
			"wrong_type",
			datasetInfo{
				Name:           "test",
				DataType:       "datetime",
				DataTypeConfig: &dataTypeConfig{},
			},
			true,
		},
		{
			"missing_config",
			datasetInfo{
				Name:     "test",
				DataType: "date",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sC.validateDateDataset(tt.dataset)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateIntegerDataset(t *testing.T) {
	sC := &structuredContext{}

	tests := []struct {
		name    string
		dataset datasetInfo
		size    int64
		wantErr bool
	}{
		{
			"valid_32",
			datasetInfo{
				Name:           "test",
				DataType:       "integer",
				DataTypeConfig: &dataTypeConfig{Size: 32},
			},
			32,
			false,
		},
		{
			"valid_64",
			datasetInfo{
				Name:           "test",
				DataType:       "integer",
				DataTypeConfig: &dataTypeConfig{Size: 64},
			},
			64,
			false,
		},
		{
			"wrong_type",
			datasetInfo{
				Name:           "test",
				DataType:       "string",
				DataTypeConfig: &dataTypeConfig{Size: 32},
			},
			32,
			true,
		},
		{
			"wrong_size",
			datasetInfo{
				Name:           "test",
				DataType:       "integer",
				DataTypeConfig: &dataTypeConfig{Size: 64},
			},
			32,
			true,
		},
		{
			"missing_config",
			datasetInfo{
				Name:     "test",
				DataType: "integer",
			},
			32,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sC.validateIntegerDataset(tt.dataset, tt.size)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
