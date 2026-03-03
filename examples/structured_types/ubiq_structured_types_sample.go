package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"gitlab.com/ubiqsecurity/ubiq-go/v2"
)

const (
	exitSuccess int = 0
	exitFailure
)

type mode int

const (
	modeEncrypt mode = iota
	modeDecrypt
)

type parameters struct {
	search, roundtrip                                          bool
	mode                                                       mode
	encrypt, decrypt, credfile, profile, datasetName, dataType string
}

func usage(args ...string) {
	status := exitSuccess
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n\n", args[0])
		status = exitFailure
	}

	fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Encrypt or decrypt typed data using the Ubiq service\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -h, -help               Show this help message and exit\n")
	fmt.Fprintf(os.Stderr, "  -V, -version            Show program's version number and exit\n")
	fmt.Fprintf(os.Stderr, "  -e, -encrypttext        Value to encrypt\n")
	fmt.Fprintf(os.Stderr, "  -d, -decrypttext        Value to decrypt\n")
	fmt.Fprintf(os.Stderr, "  -n, -datasetName        Dataset name (e.g. INT32, DATE, GENERIC_STRING_32)\n")
	fmt.Fprintf(os.Stderr, "  -t, -type               Data type: string (default), int32, int64, date, datetime\n")
	fmt.Fprintf(os.Stderr, "  -r, -roundtrip          Encrypt then decrypt (round-trip test)\n")
	fmt.Fprintf(os.Stderr, "  -s, -search             Encrypt for search\n")
	fmt.Fprintf(os.Stderr, "  -c CREDENTIALS, -creds CREDENTIALS\n")
	fmt.Fprintf(os.Stderr, "                          Credentials file (default: ~/.ubiq/credentials)\n")
	fmt.Fprintf(os.Stderr, "  -P PROFILE, -profile PROFILE\n")
	fmt.Fprintf(os.Stderr, "                          Profile within credentials file\n")

	os.Exit(status)
}

func getopts() parameters {
	var help, version bool
	var params parameters

	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	f.BoolVar(&help, "h", false, "")
	f.BoolVar(&help, "help", false, "")
	f.BoolVar(&version, "V", false, "")
	f.BoolVar(&version, "version", false, "")

	f.BoolVar(&params.search, "s", false, "")
	f.BoolVar(&params.search, "search", false, "")
	f.BoolVar(&params.roundtrip, "r", false, "")
	f.BoolVar(&params.roundtrip, "roundtrip", false, "")

	f.StringVar(&params.encrypt, "e", "", "")
	f.StringVar(&params.encrypt, "encrypttext", "", "")
	f.StringVar(&params.decrypt, "d", "", "")
	f.StringVar(&params.decrypt, "decrypttext", "", "")
	f.StringVar(&params.datasetName, "n", "", "")
	f.StringVar(&params.datasetName, "datasetName", "", "")
	f.StringVar(&params.dataType, "t", "string", "")
	f.StringVar(&params.dataType, "type", "string", "")

	f.StringVar(&params.credfile, "c", "", "")
	f.StringVar(&params.credfile, "creds", "", "")
	f.StringVar(&params.profile, "P", "", "")
	f.StringVar(&params.profile, "profile", "", "")

	f.Parse(os.Args[1:])

	if help {
		usage()
	}
	if version {
		fmt.Fprintf(os.Stderr, "version %s\n", ubiq.Version)
		os.Exit(exitSuccess)
	}

	if len(params.encrypt) > 0 && len(params.decrypt) > 0 {
		usage("please specify one of encrypt or decrypt operations")
	} else if len(params.encrypt) > 0 {
		params.mode = modeEncrypt
	} else if len(params.decrypt) > 0 {
		params.mode = modeDecrypt
	} else {
		usage("please specify encrypt (-e) or decrypt (-d) value")
	}

	if params.search && params.mode == modeDecrypt {
		usage("encrypt for search can only be used with encryption")
	}
	if params.roundtrip && params.mode == modeDecrypt {
		usage("round-trip can only be used with encryption (-e)")
	}

	return params
}

func encryptString(enc *ubiq.StructuredEncryption, dataset, plain string, search bool) error {
	if search {
		results, err := enc.CipherForSearch(dataset, plain, nil)
		if err != nil {
			return err
		}
		fmt.Printf("EncryptForSearch results:\n")
		for _, v := range results {
			fmt.Printf("\t%s\n", v)
		}
		return nil
	}
	cipher, err := enc.Cipher(dataset, plain, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %s\n", cipher)
	return nil
}

func decryptString(dec *ubiq.StructuredDecryption, dataset, cipher string) error {
	plain, err := dec.Cipher(dataset, cipher, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %s\n", plain)
	return nil
}

func encryptInt32(enc *ubiq.StructuredEncryption, dataset string, value string, search bool) error {
	v, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid int32 value %q: %w", value, err)
	}
	if search {
		results, err := enc.CipherInt32ForSearch(dataset, int32(v), nil)
		if err != nil {
			return err
		}
		fmt.Printf("EncryptForSearch results:\n")
		for _, r := range results {
			fmt.Printf("\t%d\n", r)
		}
		return nil
	}
	cipher, err := enc.CipherInt32(dataset, int32(v), nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %d\n", cipher)
	return nil
}

func decryptInt32(dec *ubiq.StructuredDecryption, dataset string, value string) error {
	v, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid int32 cipher value %q: %w", value, err)
	}
	plain, err := dec.DecipherInt32(dataset, int32(v), nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %d\n", plain)
	return nil
}

func encryptInt64(enc *ubiq.StructuredEncryption, dataset string, value string, search bool) error {
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid int64 value %q: %w", value, err)
	}
	if search {
		results, err := enc.CipherInt64ForSearch(dataset, v, nil)
		if err != nil {
			return err
		}
		fmt.Printf("EncryptForSearch results:\n")
		for _, r := range results {
			fmt.Printf("\t%d\n", r)
		}
		return nil
	}
	cipher, err := enc.CipherInt64(dataset, v, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %d\n", cipher)
	return nil
}

func decryptInt64(dec *ubiq.StructuredDecryption, dataset string, value string) error {
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid int64 cipher value %q: %w", value, err)
	}
	plain, err := dec.DecipherInt64(dataset, v, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %d\n", plain)
	return nil
}

func encryptDate(enc *ubiq.StructuredEncryption, dataset string, value string, search bool) error {
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return fmt.Errorf("invalid date %q (expected YYYY-MM-DD): %w", value, err)
	}
	if search {
		results, err := enc.CipherDateForSearch(dataset, t, nil)
		if err != nil {
			return err
		}
		fmt.Printf("EncryptForSearch results:\n")
		for _, r := range results {
			fmt.Printf("\t%s\n", r.Format("2006-01-02"))
		}
		return nil
	}
	cipher, err := enc.CipherDate(dataset, t, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %s\n", cipher.Format("2006-01-02"))
	return nil
}

func decryptDate(dec *ubiq.StructuredDecryption, dataset string, value string) error {
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return fmt.Errorf("invalid date cipher %q (expected YYYY-MM-DD): %w", value, err)
	}
	plain, err := dec.DecipherDate(dataset, t, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %s\n", plain.Format("2006-01-02"))
	return nil
}

func encryptDateTime(enc *ubiq.StructuredEncryption, dataset string, value string, search bool) error {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("invalid datetime %q (expected RFC3339): %w", value, err)
	}
	if search {
		results, err := enc.CipherDateTimeForSearch(dataset, t, nil)
		if err != nil {
			return err
		}
		fmt.Printf("EncryptForSearch results:\n")
		for _, r := range results {
			fmt.Printf("\t%s\n", r.Format(time.RFC3339))
		}
		return nil
	}
	cipher, err := enc.CipherDateTime(dataset, t, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %s\n", cipher.Format(time.RFC3339))
	return nil
}

func decryptDateTime(dec *ubiq.StructuredDecryption, dataset string, value string) error {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("invalid datetime cipher %q (expected RFC3339): %w", value, err)
	}
	plain, err := dec.DecipherDateTime(dataset, t, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %s\n", plain.Format(time.RFC3339))
	return nil
}

func roundtripString(creds ubiq.Credentials, dataset, plain string) error {
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	cipher, err := enc.Cipher(dataset, plain, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %s\n", cipher)

	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		return err
	}
	result, err := dec.Cipher(dataset, cipher, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %s\n", result)
	if result == plain {
		fmt.Printf("ROUND-TRIP: OK\n")
	} else {
		fmt.Printf("ROUND-TRIP: MISMATCH (expected %q, got %q)\n", plain, result)
	}
	return nil
}

func roundtripInt32(creds ubiq.Credentials, dataset, value string) error {
	v, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid int32 value %q: %w", value, err)
	}
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	cipher, err := enc.CipherInt32(dataset, int32(v), nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %d\n", cipher)

	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		return err
	}
	plain, err := dec.DecipherInt32(dataset, cipher, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %d\n", plain)
	if plain == int32(v) {
		fmt.Printf("ROUND-TRIP: OK\n")
	} else {
		fmt.Printf("ROUND-TRIP: MISMATCH (expected %d, got %d)\n", int32(v), plain)
	}
	return nil
}

func roundtripInt64(creds ubiq.Credentials, dataset, value string) error {
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid int64 value %q: %w", value, err)
	}
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	cipher, err := enc.CipherInt64(dataset, v, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %d\n", cipher)

	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		return err
	}
	plain, err := dec.DecipherInt64(dataset, cipher, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %d\n", plain)
	if plain == v {
		fmt.Printf("ROUND-TRIP: OK\n")
	} else {
		fmt.Printf("ROUND-TRIP: MISMATCH (expected %d, got %d)\n", v, plain)
	}
	return nil
}

func roundtripDate(creds ubiq.Credentials, dataset, value string) error {
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return fmt.Errorf("invalid date %q (expected YYYY-MM-DD): %w", value, err)
	}
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	cipher, err := enc.CipherDate(dataset, t, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %s\n", cipher.Format("2006-01-02"))

	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		return err
	}
	plain, err := dec.DecipherDate(dataset, cipher, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %s\n", plain.Format("2006-01-02"))
	if plain.Equal(t) {
		fmt.Printf("ROUND-TRIP: OK\n")
	} else {
		fmt.Printf("ROUND-TRIP: MISMATCH (expected %s, got %s)\n", t.Format("2006-01-02"), plain.Format("2006-01-02"))
	}
	return nil
}

func roundtripDateTime(creds ubiq.Credentials, dataset, value string) error {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("invalid datetime %q (expected RFC3339): %w", value, err)
	}
	enc, err := ubiq.NewStructuredEncryption(creds)
	if err != nil {
		return err
	}
	cipher, err := enc.CipherDateTime(dataset, t, nil)
	if err != nil {
		return err
	}
	fmt.Printf("ENCRYPTED: %s\n", cipher.Format(time.RFC3339))

	dec, err := ubiq.NewStructuredDecryption(creds)
	if err != nil {
		return err
	}
	plain, err := dec.DecipherDateTime(dataset, cipher, nil)
	if err != nil {
		return err
	}
	fmt.Printf("DECRYPTED: %s\n", plain.Format(time.RFC3339))
	if plain.Equal(t) {
		fmt.Printf("ROUND-TRIP: OK\n")
	} else {
		fmt.Printf("ROUND-TRIP: MISMATCH (expected %s, got %s)\n", t.Format(time.RFC3339), plain.Format(time.RFC3339))
	}
	return nil
}

func _main(params parameters) error {
	credentials, err := ubiq.NewCredentials(params.credfile, params.profile)
	if err != nil {
		return err
	}

	dataset := params.datasetName
	dtype := params.dataType

	// Round-trip mode
	if params.roundtrip {
		value := params.encrypt
		switch dtype {
		case "string":
			return roundtripString(credentials, dataset, value)
		case "int32":
			return roundtripInt32(credentials, dataset, value)
		case "int64":
			return roundtripInt64(credentials, dataset, value)
		case "date":
			return roundtripDate(credentials, dataset, value)
		case "datetime":
			return roundtripDateTime(credentials, dataset, value)
		default:
			return fmt.Errorf("unknown data type %q", dtype)
		}
	}

	// Encrypt mode
	if params.mode == modeEncrypt {
		enc, err := ubiq.NewStructuredEncryption(credentials)
		if err != nil {
			return err
		}
		switch dtype {
		case "string":
			return encryptString(enc, dataset, params.encrypt, params.search)
		case "int32":
			return encryptInt32(enc, dataset, params.encrypt, params.search)
		case "int64":
			return encryptInt64(enc, dataset, params.encrypt, params.search)
		case "date":
			return encryptDate(enc, dataset, params.encrypt, params.search)
		case "datetime":
			return encryptDateTime(enc, dataset, params.encrypt, params.search)
		default:
			return fmt.Errorf("unknown data type %q", dtype)
		}
	}

	// Decrypt mode
	dec, err := ubiq.NewStructuredDecryption(credentials)
	if err != nil {
		return err
	}
	switch dtype {
	case "string":
		return decryptString(dec, dataset, params.decrypt)
	case "int32":
		return decryptInt32(dec, dataset, params.decrypt)
	case "int64":
		return decryptInt64(dec, dataset, params.decrypt)
	case "date":
		return decryptDate(dec, dataset, params.decrypt)
	case "datetime":
		return decryptDateTime(dec, dataset, params.decrypt)
	default:
		return fmt.Errorf("unknown data type %q", dtype)
	}
}

func main() {
	err := _main(getopts())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitFailure)
	}
}
