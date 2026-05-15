package ubiq

import (
	"fmt"
	"strconv"
	"time"
)

const (
	inferredDateLayout     = "2006-01-02T15:04Z"
	inferredDateTimeLayout = time.RFC3339
)

// inferredCipher encrypts plainText by dispatching to the typed cipher matching
// the dataset's DataType (integer/date/datetime), or to the string Cipher for
// anything else. plainText and the returned ciphertext are formatted exactly
// like the corresponding typed APIs (decimal for integers, "YYYY-MM-DDTHH:MMZ"
// for dates, RFC3339 for datetimes). Internal: matches .NET's internal
// InferredEncryptAsync; used by tests to drive fixture-based round-trips.
func (se *StructuredEncryption) inferredCipher(datasetName, plainText string, tweak []byte) (string, error) {
	sC := (*structuredContext)(se)
	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return "", err
	}

	switch dataset.DataType {
	case "integer":
		if dataset.DataTypeConfig == nil {
			return "", fmt.Errorf("dataset %q is missing data_type_config", datasetName)
		}
		v, err := strconv.ParseInt(plainText, 10, 64)
		if err != nil {
			return "", fmt.Errorf("parse integer plaintext %q: %w", plainText, err)
		}
		switch dataset.DataTypeConfig.Size {
		case 32:
			ct, err := sC.encryptInt32(dataset, int32(v), tweak, -1)
			if err != nil {
				return "", err
			}
			return strconv.FormatInt(int64(ct), 10), nil
		case 64:
			ct, err := sC.encryptInt64(dataset, v, tweak, -1)
			if err != nil {
				return "", err
			}
			return strconv.FormatInt(ct, 10), nil
		default:
			return "", fmt.Errorf("dataset %q has unsupported integer size %d", datasetName, dataset.DataTypeConfig.Size)
		}

	case "date":
		t, err := time.Parse(inferredDateLayout, plainText)
		if err != nil {
			return "", fmt.Errorf("parse date plaintext %q: %w", plainText, err)
		}
		ct, err := sC.encryptDate(dataset, t, tweak, -1)
		if err != nil {
			return "", err
		}
		return ct.UTC().Format(inferredDateLayout), nil

	case "datetime":
		t, err := time.Parse(inferredDateTimeLayout, plainText)
		if err != nil {
			return "", fmt.Errorf("parse datetime plaintext %q: %w", plainText, err)
		}
		ct, err := sC.encryptDateTime(dataset, t, tweak, -1)
		if err != nil {
			return "", err
		}
		return ct.UTC().Format(inferredDateTimeLayout), nil

	default:
		return se.Cipher(datasetName, plainText, tweak)
	}
}

// inferredDecipher decrypts cipherText by dispatching to the typed decipher
// matching the dataset's DataType. The cipherText must be in the format
// produced by the corresponding typed API (see inferredCipher). Internal:
// matches .NET's internal InferredDecryptAsync.
func (sd *StructuredDecryption) inferredDecipher(datasetName, cipherText string, tweak []byte) (string, error) {
	sC := (*structuredContext)(sd)
	dataset, err := sC.fetchDataset(datasetName)
	if err != nil {
		return "", err
	}

	switch dataset.DataType {
	case "integer":
		if dataset.DataTypeConfig == nil {
			return "", fmt.Errorf("dataset %q is missing data_type_config", datasetName)
		}
		v, err := strconv.ParseInt(cipherText, 10, 64)
		if err != nil {
			return "", fmt.Errorf("parse integer ciphertext %q: %w", cipherText, err)
		}
		switch dataset.DataTypeConfig.Size {
		case 32:
			pt, err := sC.decryptInt32(dataset, int32(v), tweak)
			if err != nil {
				return "", err
			}
			return strconv.FormatInt(int64(pt), 10), nil
		case 64:
			pt, err := sC.decryptInt64(dataset, v, tweak)
			if err != nil {
				return "", err
			}
			return strconv.FormatInt(pt, 10), nil
		default:
			return "", fmt.Errorf("dataset %q has unsupported integer size %d", datasetName, dataset.DataTypeConfig.Size)
		}

	case "date":
		t, err := time.Parse(inferredDateLayout, cipherText)
		if err != nil {
			return "", fmt.Errorf("parse date ciphertext %q: %w", cipherText, err)
		}
		pt, err := sC.decryptDate(dataset, t, tweak)
		if err != nil {
			return "", err
		}
		return pt.UTC().Format(inferredDateLayout), nil

	case "datetime":
		t, err := time.Parse(inferredDateTimeLayout, cipherText)
		if err != nil {
			return "", fmt.Errorf("parse datetime ciphertext %q: %w", cipherText, err)
		}
		pt, err := sC.decryptDateTime(dataset, t, tweak)
		if err != nil {
			return "", err
		}
		return pt.UTC().Format(inferredDateTimeLayout), nil

	default:
		return sd.Cipher(datasetName, cipherText, tweak)
	}
}
