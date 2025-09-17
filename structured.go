package ubiq

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"

	"gitlab.com/ubiqsecurity/ubiq-go/v2/structured"
)

type datasetInfo struct {
	Name                    string `json:"name"`
	Type                    string `json:"fpe_definable_type"`
	Algorithm               string `json:"encryption_algorithm"`
	PassthroughCharacterSet string `json:"passthrough"`
	PassthroughAlphabet     structured.Alphabet
	OutputCharacterSet      string `json:"output_character_set"`
	OutputAlphabet          structured.Alphabet
	InputCharacterSet       string `json:"input_character_set"`
	InputAlphabet           structured.Alphabet
	InputLengthMin          int               `json:"min_input_length"`
	InputLengthMax          int               `json:"max_input_length"`
	NumEncodingBits         int               `json:"msb_encoding_bits"`
	Salt                    string            `json:"salt"`
	Tweak                   string            `json:"tweak"`
	TweakLengthMax          int               `json:"tweak_max_len"`
	TweakLengthMin          int               `json:"tweak_min_len"`
	TweakSource             string            `json:"tweak_source"`
	PassthroughRules        []passthroughRule `json:"passthrough_rules"`
}

type passthroughRule struct {
	Type     string      `json:"type"`
	Value    interface{} `json:"value"`
	Priority int         `json:"priority"`
	Buffer   []rune
}

type defKeys struct {
	CurrentKeyNum       int         `json:"current_key_number"`
	EncryptedPrivateKey string      `json:"encrypted_private_key"`
	Dataset             datasetInfo `json:"ffs"`
	EncryptedDataKeys   []string    `json:"keys"`
	Retrieved           float32     `json:"retrieved"`
}

// this interface was created so that it could be placed into
// the structuredContext so that structuredContext could be used in both encryption
// and decryption operations
//
// its a convenience for this code and should follow whatever interfaces
// are provided by the underlying library rather than dictating what
// the underlying library should look like/present
type structuredAlgorithm interface {
	// the encrypt and decrypt interfaces aren't used because,
	// internally, it's easier to deal with runes and avoid the
	// back and forth conversions to strings
	Encrypt(string, []byte) (string, error)
	Decrypt(string, []byte) (string, error)

	EncryptRunes([]rune, []byte) ([]rune, error)
	DecryptRunes([]rune, []byte) ([]rune, error)
}

type structuredContext struct {
	// object/data for dealing with the server
	client           httpClient
	host, papi, srsa string
	config           *Configuration
	cache            *cache
	creds            *Credentials

	// information about the format of the data
	// DEPRECATED: Do not use, only here for legacy FPE compatibility
	dataset datasetInfo

	// the key number and algorithm
	// a key number of -1 indicates that the key
	// number and algorithm are not set
	// kn   int
	// algo structuredAlgorithm

	tracking trackingContext
}

type structuredKey struct {
	Num int    `json:"num"`
	Key []byte `json:"key"`
	WDK string `json:"wdk"`
	EPK string `json:"epk"`
}

// Reusable object to preserve context across
// multiple encryptions using the same format
type StructuredEncryption structuredContext

// Reusable object to preserve context across
// multiple decryptions using the same format
type StructuredDecryption structuredContext

// retrieve the format information from the server
func (sC *structuredContext) fetchDataset(name string) (datasetInfo, error) {
	var err error
	var dataset *datasetInfo
	var fromCache bool

	cacheKey := getStructuredDatasetKey(sC.papi, name)

	if sC.config.KeyCaching.Structured {
		cachedDataset, err := sC.cache.readDataset(cacheKey)
		if err != nil {
			if !errors.Is(err, ErrNotInCache) {
				return datasetInfo{}, err
			}
		} else {
			dataset = &cachedDataset
			fromCache = true
		}
	}

	if err != nil || dataset == nil {
		var query = "ffs_name=" + url.QueryEscape(name) + "&" +
			"papi=" + url.QueryEscape(sC.papi)

		var rsp *http.Response

		rsp, err = sC.client.Get(sC.host + "/api/v0/ffs?" + query)
		if err != nil {
			return datasetInfo{}, err
		}
		defer rsp.Body.Close()

		if rsp.StatusCode == http.StatusOK {
			dataset = new(datasetInfo)
			err = json.NewDecoder(rsp.Body).Decode(dataset)
		} else {
			errMsg, _ := io.ReadAll(rsp.Body)
			err = fmt.Errorf("unexpected response: " + string(errMsg))
		}
		if err != nil {
			return datasetInfo{}, err
		}

	}

	// convert the character string to arrays of runes
	// to enable unicode handling
	dataset.PassthroughAlphabet, _ =
		structured.NewAlphabet(dataset.PassthroughCharacterSet)
	dataset.OutputAlphabet, _ =
		structured.NewAlphabet(dataset.OutputCharacterSet)
	dataset.InputAlphabet, _ =
		structured.NewAlphabet(dataset.InputCharacterSet)

	if sC.config.KeyCaching.Structured && !fromCache {
		sC.cache.updateDataset(cacheKey, *dataset)
	}

	return *dataset, nil
}

func (sC *structuredContext) flushDataset(papi, name *string) {
	if sC.config.KeyCaching.Structured {
		sC.cache.cache.Delete(getStructuredDatasetKey(*papi, *name))
	}
}

// retrieve the key from the server
func (sC *structuredContext) fetchKey(name string, n int) (
	structuredKey, error) {
	var err error
	var key *structuredKey
	var fromCache bool

	cacheKey := getStructuredCacheKey(sC.papi, name, n)
	if sC.config.KeyCaching.Structured {
		cacheResult, err := sC.cache.readStructuredKey(cacheKey)
		if err != nil {
			if !errors.Is(err, ErrNotInCache) {
				return structuredKey{}, err
			}
		} else {
			key = &cacheResult
			fromCache = true
		}
	}

	var obj struct {
		EPK string `json:"encrypted_private_key"`
		WDK string `json:"wrapped_data_key"`
		Num string `json:"key_number"`
	}

	if err != nil || key == nil {
		if sC.config.Logging.Verbose {
			fmt.Fprintf(os.Stdout, "EXPENSIVE --- Fetching Key %v %v From API\n", name, n)
		}
		query := url.Values{}
		query.Set("ffs_name", name)
		query.Set("papi", sC.papi)

		var rsp *http.Response

		if n >= 0 {
			query.Set("key_number", strconv.Itoa((n)))
		}

		isIdp, err := sC.creds.isIdp()

		if err != nil {
			return structuredKey{}, err
		}

		if isIdp {
			// IDP mode requires passing the idp cert to the server
			sC.creds.renewIdpCert()
			query.Set("payload_cert", sC.creds.idpBase64Cert)
		}

		rsp, err = sC.client.Get(sC.host + "/api/v0/fpe/key?" + query.Encode())
		if err != nil {
			return structuredKey{}, err
		}
		defer rsp.Body.Close()

		if rsp.StatusCode == http.StatusOK {
			err = json.NewDecoder(rsp.Body).Decode(&obj)
		} else {
			errMsg, _ := io.ReadAll(rsp.Body)
			err = fmt.Errorf("unexpected response: " + string(errMsg))
		}
		if err != nil {
			return structuredKey{}, err
		}
		key = new(structuredKey)
		if isIdp {
			// IDP mode has a local private key, need to override that key since nothing will be returned from server
			key.EPK = sC.creds.idpEncryptedPrivateKey
		} else {
			key.EPK = obj.EPK
		}
		key.WDK = obj.WDK
		key.Num, _ = strconv.Atoi(obj.Num)
	}

	// Store without unwrapped data key if Encrypt
	if sC.config.KeyCaching.Structured && sC.config.KeyCaching.Encrypt && !fromCache {
		sC.cache.updateStructuredKey(cacheKey, *key)
		// If -1, it is the current key. Also store at the key number.
		if n == -1 {
			sC.cache.updateStructuredKey(getStructuredCacheKey(sC.papi, name, key.Num), *key)
		}
	}

	// If key is empty, either encrypted cache or fresh pull
	if len(key.Key) == 0 {
		key.Key, err = unwrapDataKey(key.WDK, key.EPK, sC.srsa)
		if err != nil {
			return structuredKey{}, err
		}
	}

	// Store unwrapped if not encrypted
	if sC.config.KeyCaching.Structured && !sC.config.KeyCaching.Encrypt && !fromCache {
		sC.cache.updateStructuredKey(cacheKey, *key)
		// If -1, it is the current key. Also store at the key number.
		if n == -1 {
			sC.cache.updateStructuredKey(getStructuredCacheKey(sC.papi, name, key.Num), *key)
		}
	}

	return *key, nil
}

// Retrieve all keys from the server
func (sC *structuredContext) fetchAllKeys(name string) (
	keys []structuredKey, err error) {

	query := url.Values{}
	query.Set("ffs_name", name)
	query.Set("papi", sC.papi)

	isIdp, err := sC.creds.isIdp()

	if err != nil {
		return nil, err
	}

	if isIdp {
		// IDP mode requires passing the idp cert to the server
		sC.creds.renewIdpCert()
		query.Set("payload_cert", sC.creds.idpBase64Cert)
	}

	var rsp *http.Response

	rsp, err = sC.client.Get(sC.host + "/api/v0/fpe/def_keys?" + query.Encode())
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	js := make(map[string]defKeys)
	json.NewDecoder(rsp.Body).Decode(&js)

	var epk string
	if isIdp {
		// IDP mode has a local private key, need to override that key since nothing will be returned from server
		epk = sC.creds.idpEncryptedPrivateKey
	} else {
		epk = js[name].EncryptedPrivateKey
	}

	pk, err := decryptPrivateKey(epk, sC.srsa)
	if err != nil {
		return nil, err
	}

	shouldCache := sC.config.KeyCaching.Structured
	shouldEncrypt := sC.config.KeyCaching.Encrypt

	keys = make([]structuredKey, len(js[name].EncryptedDataKeys))
	for i := range js[name].EncryptedDataKeys {
		var key structuredKey

		key.Num = i
		key.EPK = epk
		key.WDK = js[name].EncryptedDataKeys[i]

		cacheKey := getStructuredCacheKey(sC.papi, name, i)

		// Store without decrypted data key if encrypted
		if shouldCache && shouldEncrypt {
			sC.cache.updateStructuredKey(cacheKey, key)
		}

		key.Key, err = decryptDataKey(
			js[name].EncryptedDataKeys[i], pk)
		if err != nil {
			return nil, err
		}

		if shouldCache && !shouldEncrypt {
			sC.cache.updateStructuredKey(cacheKey, key)
		}

		keys[i] = key
	}

	return keys, nil
}

func (sC *structuredContext) flushKey(papi, name *string, n int) {
	if sC.config.KeyCaching.Structured {
		cacheKey := getStructuredCacheKey(*papi, *name, n)
		sC.cache.cache.Delete(cacheKey)
	}
}

// convert a string representation of a number (@inp) in the radix/alphabet
// described by @ics to the radix/alphabet described by @ocs
func convertRadix(inp []rune, ics, ocs *structured.Alphabet) []rune {
	var n *big.Int = big.NewInt(0)
	return structured.BigIntToRunes(ocs,
		structured.RunesToBigInt(n, ics, inp), len(inp))
}

// remove passthrough characters from the input and preserve the format
// so the output can be reformatted after encryption/decryption
func formatInput(inp []rune, pth *structured.Alphabet, icr *structured.Alphabet, ocr0 rune, rules []passthroughRule) (fmtr []rune, out []rune, updatedRules []passthroughRule, err error) {
	// Rules may contain updated information (buffer value)
	updatedRules = rules

	if pth.Len() > 0 && len(rules) == 0 {
		var pthRule passthroughRule
		pthRule.Priority = 1
		pthRule.Type = "passthrough"
		pthRule.Value = "legacy"
		updatedRules = append(updatedRules, pthRule)
	}

	// Sort the rules by priority (asc)
	sort.Slice(updatedRules[:], func(i, j int) bool {
		return updatedRules[i].Priority < updatedRules[j].Priority
	})

	// Make copy to avoid issues with manipulating the original input
	out = make([]rune, len(inp))
	copy(out, inp)

	for idx, rule := range updatedRules {
		switch rule.Type {
		case "passthrough":
			var pthOut []rune
			// If we don't have a legacy pth Alphabet, create one now with the passthrough rule's Value
			pthRule := rule.Value.(string)
			if pth.Len() == 0 && pthRule != "legacy" && len(pthRule) > 0 {
				pthAlpha, _ := structured.NewAlphabet(pthRule)
				pth = &pthAlpha
			}
			for _, c := range out {
				if pth.PosOf(c) >= 0 {
					fmtr = append(fmtr, c)
				} else {
					fmtr = append(fmtr, ocr0)
					pthOut = append(pthOut, c)
				}
			}
			out = pthOut
		case "prefix":
			prefix := int(rule.Value.(float64))
			if prefix > 0 {
				// Store removed portion in rule.
				rule.Buffer = make([]rune, prefix)
				copy(rule.Buffer, out[0:prefix:prefix])

				updatedRules[idx] = rule
				out = out[prefix:]
			}
		case "suffix":
			suf := int(rule.Value.(float64))
			if suf > 0 {
				suffix := len(out) - suf

				// Store removed portion in rule.
				rule.Buffer = make([]rune, len(out))
				copy(rule.Buffer, out[suffix:len(out):len(out)])

				updatedRules[idx] = rule
				out = out[:suffix]
			}
		default:
			err = fmt.Errorf("ubiq go library does not support rule type \"%v\" at this time", rule.Type)
		}
	}

	if !validateCharset(out, icr) {
		err = errors.New("invalid input string character(s)")
	}

	return
}

func validateCharset(input []rune, charset *structured.Alphabet) bool {
	for _, c := range input {
		if charset.PosOf(c) == -1 {
			return false
		}
	}

	return true
}

// reinsert passthrough characters into output
func formatOutput(fmtr []rune, inp []rune, pth *structured.Alphabet, rules []passthroughRule) (out []rune, err error) {
	// Sort the rules by priority (desc)
	sort.Slice(rules[:], func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	// Make copy to avoid issues with manipulating the original input
	out = make([]rune, len(inp))
	copy(out, inp)

	for _, rule := range rules {
		switch rule.Type {
		case "passthrough":
			var pth_out []rune
			for _, c := range fmtr {
				if pth.PosOf(c) >= 0 {
					pth_out = append(pth_out, c)
				} else {
					pth_out = append(pth_out, out[0])
					out = out[1:]
				}
			}

			if len(out) > 0 {
				err = errors.New("mismatched format and output strings")
			}
			out = pth_out
		case "prefix":
			out = append(rule.Buffer, out...)
		case "suffix":
			out = append(out, rule.Buffer...)
		default:
			err = errors.New("invalid rule type")
		}
	}

	return
}

// encode the key number into a ciphertext
func encodeKeyNumber(inp []rune, ocs *structured.Alphabet, n, sft int) []rune {
	idx := ocs.PosOf(inp[0])
	idx += n << sft

	inp[0] = ocs.ValAt(idx)
	return inp
}

// recover the key number from a ciphertext
func decodeKeyNumber(inp []rune, ocs *structured.Alphabet, sft int) ([]rune, int) {
	c := ocs.PosOf(inp[0])
	n := c >> sft

	inp[0] = ocs.ValAt(c - (n << sft))
	return inp, n
}

func newStructuredContext(c Credentials) (fc *structuredContext, err error) {
	fc = new(structuredContext)

	fc.client = newHttpClient(c)

	fc.host, _ = c.host()
	fc.papi, _ = c.papi()
	fc.srsa, _ = c.srsa()
	fc.config = c.config
	fc.cache = &c.cache
	fc.creds = &c
	return
}

func (fc *structuredContext) getAlgorithm(dataset datasetInfo, key, twk []byte) (
	alg structuredAlgorithm, err error) {
	if dataset.Algorithm == "FF1" {
		alg, err = structured.NewFF1(
			key, twk,
			dataset.TweakLengthMin, dataset.TweakLengthMax,
			dataset.InputAlphabet.Len(),
			dataset.InputCharacterSet)
	} else {
		err = errors.New("unsupported algorithm: " + dataset.Algorithm)
	}

	return
}

// retrieve algorithm and key information from the server
//
// for encryption this can be done right away as the key number is
// unknown. for decryption, it can't be done until the ciphertext
// has been presented and the key number decoded from it
func (fc *structuredContext) setAlgorithm(dataset datasetInfo, kn int) (algo structuredAlgorithm, currKeyNum int, err error) {
	var twk []byte
	var key structuredKey

	twk, err = base64.StdEncoding.DecodeString(dataset.Tweak)
	if err != nil {
		return
	}

	key, err = fc.fetchKey(dataset.Name, kn)
	if err != nil {
		return
	}

	algo, err = fc.getAlgorithm(dataset, key.Key, twk)
	if err == nil {
		currKeyNum = key.Num
	}
	return
}

// Create a new format preserving encryption object. The returned object
// can be reused to encrypt multiple plaintexts using the format (and
// algorithm and key) named by @dataset
func NewStructuredEncryption(c Credentials) (*StructuredEncryption, error) {
	var err error

	fc, err := newStructuredContext(c)
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host, c.config)
	}

	return (*StructuredEncryption)(fc), err
}

// Encrypt a plaintext string using the key, algorithm, and format
// preserving parameters defined by the encryption object.
//
// @twk may be nil, in which case, the default will be used
func (fe *StructuredEncryption) Cipher(datasetName, pt string, twk []byte) (
	ct string, err error) {
	dataset, err := ((*structuredContext)(fe)).fetchDataset(datasetName)
	// fe.dataset = dataset
	if err != nil {
		return
	}
	algo, kn, err := ((*structuredContext)(fe)).setAlgorithm(dataset, -1)
	if err != nil {
		return
	}

	var fmtr, ptr, ctr []rune
	var rules []passthroughRule

	fmtr, ptr, rules, err = formatInput(
		[]rune(pt),
		&dataset.PassthroughAlphabet,
		&dataset.InputAlphabet,
		dataset.OutputAlphabet.ValAt(0), dataset.PassthroughRules)

	if err != nil {
		return
	}

	if len(ptr) < dataset.InputLengthMin || len(ptr) > dataset.InputLengthMax {
		err = fmt.Errorf("invalid input length (%v) min: %v max %v", len(ptr), dataset.InputLengthMin, dataset.InputLengthMax)
		return
	}

	ctr, err = algo.EncryptRunes(ptr, twk)
	if err != nil {
		return
	}

	fe.tracking.AddEvent(
		fe.papi, dataset.Name, "",
		trackingActionEncrypt,
		1, kn)

	ctr = convertRadix(ctr, &dataset.InputAlphabet, &dataset.OutputAlphabet)
	ctr = encodeKeyNumber(
		ctr, &dataset.OutputAlphabet, kn, dataset.NumEncodingBits)
	ctr, err = formatOutput(fmtr, ctr, &dataset.PassthroughAlphabet, rules)

	return string(ctr), err
}

// Encrypt a plaintext string using algorithm, format
// preserving parameters, and all keys defined by the
// encryption object.
//
// @twk may be nil, in which case, the default will be used
func (fe *StructuredEncryption) CipherForSearch(datasetName, pt string, twk []byte) (
	ct []string, err error) {
	dataset, err := ((*structuredContext)(fe)).getDatasetInfo(datasetName)

	if err != nil {
		return
	}

	// algo, kn, err := ((*structuredContext)(fe)).setAlgorithm(dataset, -1)
	// if err != nil {
	// 	return
	// }

	var fmtr, ptr, ctr []rune
	var rules []passthroughRule

	deftwk, err := base64.StdEncoding.DecodeString(dataset.Tweak)
	if err != nil {
		return
	}

	keys, err := ((*structuredContext)(fe)).fetchAllKeys(datasetName)
	if err != nil {
		return
	}

	fmtr, ptr, rules, err = formatInput(
		[]rune(pt),
		&dataset.PassthroughAlphabet,
		&dataset.InputAlphabet,
		dataset.OutputAlphabet.ValAt(0),
		dataset.PassthroughRules)
	if err != nil {
		return
	}
	if len(ptr) < dataset.InputLengthMin || len(ptr) > dataset.InputLengthMax {
		err = errors.New("input length out of bounds")
		return
	}

	ct = make([]string, len(keys))
	_ptr := make([]rune, len(ptr))
	for i := range keys {
		var alg structuredAlgorithm

		alg, err = ((*structuredContext)(fe)).getAlgorithm(dataset, keys[i].Key, deftwk)
		if err != nil {
			return
		}

		copy(_ptr, ptr)
		ctr, err = alg.EncryptRunes(_ptr, twk)
		if err != nil {
			return
		}

		fe.tracking.AddEvent(fe.papi, dataset.Name, "", trackingActionEncrypt, 1, i)

		ctr = convertRadix(ctr, &dataset.InputAlphabet, &dataset.OutputAlphabet)
		ctr = encodeKeyNumber(
			ctr, &dataset.OutputAlphabet, i, dataset.NumEncodingBits)
		ctr, err = formatOutput(fmtr, ctr, &dataset.PassthroughAlphabet, rules)

		if err != nil {
			return
		}

		ct[i] = string(ctr)
	}

	return
}

func (fe *StructuredEncryption) Close() {
	fe.tracking.Close()
	fe.cache = nil
}

// Attach metadata to usage information reported by the application.
func (fe *StructuredEncryption) AddUserDefinedMetadata(data string) error {
	return fe.tracking.AddUserDefinedMetadata(data)
}

// Create a new format preserving decryption object. The returned object
// can be reused to decrypt multiple ciphertexts using the format (and
// algorithm and key) named by @dataset
// Uses default configuration
func NewStructuredDecryption(c Credentials) (*StructuredDecryption, error) {
	var err error
	fc, err := newStructuredContext(c)
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host, c.config)
	}

	return (*StructuredDecryption)(fc), err
}

// Decrypt a ciphertext string using the key, algorithm, and format
// preserving parameters defined by the decryption object.
//
// @twk may be nil, in which case, the default will be used. Regardless,
// the tweak must match the one used during encryption of the plaintext
func (fd *StructuredDecryption) Cipher(datasetName, ct string, twk []byte) (
	pt string, err error) {
	dataset, err := ((*structuredContext)(fd)).getDatasetInfo(datasetName)
	if err != nil {
		return
	}

	var fmtr, ctr []rune
	var kn int
	var rules []passthroughRule

	fmtr, ctr, rules, err = formatInput(
		[]rune(ct),
		&dataset.PassthroughAlphabet,
		&dataset.OutputAlphabet,
		dataset.InputAlphabet.ValAt(0),
		dataset.PassthroughRules)

	if err != nil {
		return
	}

	ctr, kn = decodeKeyNumber(ctr, &dataset.OutputAlphabet, dataset.NumEncodingBits)
	algo, retKn, err := (*structuredContext)(fd).setAlgorithm(dataset, kn)
	if err != nil {
		return
	}

	ctr = convertRadix(ctr, &dataset.OutputAlphabet, &dataset.InputAlphabet)

	ptr, err := algo.DecryptRunes(ctr, twk)
	if err != nil {
		return
	}

	fd.tracking.AddEvent(
		fd.papi, dataset.Name, "",
		trackingActionDecrypt,
		1, retKn)

	ptr, err = formatOutput(fmtr, ptr, &dataset.PassthroughAlphabet, rules)

	return string(ptr), err
}

func (fd *StructuredDecryption) Close() {
	fd.tracking.Close()
	fd.cache = nil
}

// Attach metadata to usage information reported by the application.
func (fd *StructuredDecryption) AddUserDefinedMetadata(data string) error {
	return fd.tracking.AddUserDefinedMetadata(data)
}

func (sC *structuredContext) listCacheValues() error {
	iter := sC.cache.cache.Iterator()
	var isNext bool
	isNext = iter.SetNext()
	for isNext {
		entry, err := iter.Value()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%v - size: %v\n", entry.Key(), len(entry.Value()))
		isNext = iter.SetNext()
	}

	return nil
}
