package ubiq

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"

	"gitlab.com/ubiqsecurity/ubiq-go/structured"
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

	// information about the format of the data
	dataset datasetInfo

	// the key number and algorithm
	// a key number of -1 indicates that the key
	// number and algorithm are not set
	kn   int
	algo structuredAlgorithm

	tracking trackingContext
}

type structuredKey struct {
	num int
	key []byte
}

// Reusable object to preserve context across
// multiple encryptions using the same format
type StructuredEncryption structuredContext

// Reusable object to preserve context across
// multiple decryptions using the same format
type StructuredDecryption structuredContext

// datasetCache is indexed first by the public api key and then
// by the format name. objects in the map(s) are stored as
// pointers to reduce the expense of fetching them, and also
// so that they can be updated in place.
var datasetCache map[string]*map[string]*datasetInfo

func fetchDataset(client *httpClient, host, papi, name string) (datasetInfo, error) {
	var err error
	var ok bool

	if datasetCache == nil {
		datasetCache = make(map[string]*map[string]*datasetInfo)
	}

	if _, ok = datasetCache[papi]; !ok {
		m := make(map[string]*datasetInfo)
		datasetCache[papi] = &m
	}

	if _, ok = (*datasetCache[papi])[name]; !ok {
		var query = "ffs_name=" + url.QueryEscape(name) + "&" +
			"papi=" + url.QueryEscape(papi)

		var rsp *http.Response
		var dataset *datasetInfo

		rsp, err = client.Get(host + "/api/v0/ffs?" + query)
		if err != nil {
			return datasetInfo{}, err
		}
		defer rsp.Body.Close()

		if rsp.StatusCode == http.StatusOK {
			dataset = new(datasetInfo)
			err = json.NewDecoder(rsp.Body).Decode(dataset)
		} else {
			err = errors.New("unexpected response: " + rsp.Status)
		}
		if err != nil {
			return datasetInfo{}, err
		}

		if err == nil {
			// convert the character string to arrays of runes
			// to enable unicode handling
			dataset.PassthroughAlphabet, _ =
				structured.NewAlphabet(dataset.PassthroughCharacterSet)
			dataset.OutputAlphabet, _ =
				structured.NewAlphabet(dataset.OutputCharacterSet)
			dataset.InputAlphabet, _ =
				structured.NewAlphabet(dataset.InputCharacterSet)
		}

		(*datasetCache[papi])[name] = dataset
	}

	return *(*datasetCache[papi])[name], nil
}

func flushDataset(papi, name *string) {
	if datasetCache == nil {
		datasetCache = make(map[string]*map[string]*datasetInfo)
	}

	if papi == nil {
		datasetCache = make(map[string]*map[string]*datasetInfo)
	} else if m, ok := datasetCache[*papi]; ok {
		if name == nil {
			delete(datasetCache, *papi)
		} else if _, ok := (*m)[*name]; ok {
			delete(*m, *name)
		}
	}
}

// keyCache is indexed by public api, then by the format name,
// and finally by the key number. items in the map are pointers
// to allow updating in place and more efficient fetching (e.g.
// pointers instead of copies of the objects)
var keyCache map[string](*map[string](*map[int]*structuredKey))

func fetchKey(client *httpClient, host, papi, srsa, name string, n int) (
	structuredKey, error) {
	var ok bool
	var err error

	if keyCache == nil {
		keyCache = make(map[string](*map[string](*map[int]*structuredKey)))
	}
	if _, ok = keyCache[papi]; !ok {
		m := make(map[string](*map[int]*structuredKey))
		keyCache[papi] = &m
	}
	if _, ok = (*keyCache[papi])[name]; !ok {
		m := make(map[int]*structuredKey)
		(*keyCache[papi])[name] = &m
	}

	if _, ok = (*(*keyCache[papi])[name])[n]; !ok {
		var query = "ffs_name=" + url.QueryEscape(name) + "&" +
			"papi=" + url.QueryEscape(papi)

		var key structuredKey
		var rsp *http.Response
		var obj struct {
			EPK string `json:"encrypted_private_key"`
			WDK string `json:"wrapped_data_key"`
			Num string `json:"key_number"`
		}

		if n >= 0 {
			query += "&key_number=" + strconv.Itoa(n)
		}

		rsp, err = client.Get(host + "/api/v0/fpe/key?" + query)
		if err != nil {
			return structuredKey{}, err
		}
		defer rsp.Body.Close()

		if rsp.StatusCode == http.StatusOK {
			err = json.NewDecoder(rsp.Body).Decode(&obj)
		} else {
			err = errors.New("unexpected response: " + rsp.Status)
		}
		if err != nil {
			return structuredKey{}, err
		}

		key.num, _ = strconv.Atoi(obj.Num)
		key.key, err = unwrapDataKey(obj.WDK, obj.EPK, srsa)
		if err != nil {
			return structuredKey{}, err
		}

		(*(*keyCache[papi])[name])[key.num] = &key
		if n < 0 {
			(*(*keyCache[papi])[name])[-1] = &key
		}
	}

	return *(*(*keyCache[papi])[name])[n], nil
}

func fetchAllKeys(client *httpClient, host, papi, srsa, name string) (
	keys []structuredKey, err error) {
	var query = "ffs_name=" + url.QueryEscape(name) + "&" +
		"papi=" + url.QueryEscape(papi)

	var rsp *http.Response
	var ok bool

	rsp, err = client.Get(host + "/api/v0/fpe/def_keys?" + query)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	js := make(map[string]defKeys)
	json.NewDecoder(rsp.Body).Decode(&js)

	pk, err := decryptPrivateKey(js[name].EncryptedPrivateKey, srsa)
	if err != nil {
		return nil, err
	}

	if keyCache == nil {
		keyCache = make(map[string](*map[string](*map[int]*structuredKey)))
	}
	if _, ok = keyCache[papi]; !ok {
		m := make(map[string](*map[int]*structuredKey))
		keyCache[papi] = &m
	}
	if _, ok = (*keyCache[papi])[name]; !ok {
		m := make(map[int]*structuredKey)
		(*keyCache[papi])[name] = &m
	}

	keys = make([]structuredKey, len(js[name].EncryptedDataKeys))
	for i := range js[name].EncryptedDataKeys {
		if _, ok := (*(*keyCache[papi])[name])[i]; !ok {
			var key structuredKey

			key.num = i
			key.key, err = decryptDataKey(
				js[name].EncryptedDataKeys[i], pk)
			if err != nil {
				return nil, err
			}

			(*(*keyCache[papi])[name])[i] = &key
		}

		keys[i] = *(*(*keyCache[papi])[name])[i]
	}

	return keys, nil
}

func flushKey(papi, name *string, n int) {
	if keyCache == nil {
		keyCache = make(map[string](*map[string](*map[int]*structuredKey)))
	}
	if papi == nil {
		keyCache = make(map[string](*map[string](*map[int]*structuredKey)))
	} else if _, ok := keyCache[*papi]; ok {
		if name == nil {
			delete(keyCache, *papi)
		} else if _, ok := (*keyCache[*papi])[*name]; ok {
			if n < 0 {
				delete(*keyCache[*papi], *name)
			} else if _, ok := (*(*keyCache[*papi])[*name])[n]; ok {
				delete(*(*keyCache[*papi])[*name], n)
			}
		}
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
	out = []rune(inp)

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
				rule.Buffer = out[0:prefix]
				updatedRules[idx] = rule
				out = out[prefix:]
			}
		case "suffix":
			suf := int(rule.Value.(float64))
			if suf > 0 {
				suffix := len(out) - suf
				// Store removed portion in rule.
				rule.Buffer = out[suffix:]
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

	out = []rune(inp)
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

// retrieve the format information from the server
func (fc *structuredContext) getDatasetInfo(name string) (dataset datasetInfo, err error) {
	return fetchDataset(&fc.client, fc.host, fc.papi, name)
}

// retrieve the key from the server
func (fc *structuredContext) getKey(kn int) (key structuredKey, err error) {
	return fetchKey(&fc.client,
		fc.host, fc.papi, fc.srsa,
		fc.dataset.Name, kn)
}

func (fc *structuredContext) getAllKeys() (keys []structuredKey, err error) {
	return fetchAllKeys(&fc.client,
		fc.host, fc.papi, fc.srsa,
		fc.dataset.Name)
}

func newStructuredContext(c Credentials, dataset string) (fc *structuredContext, err error) {
	fc = new(structuredContext)

	fc.client = newHttpClient(c)

	fc.host, _ = c.host()
	fc.papi, _ = c.papi()
	fc.srsa, _ = c.srsa()

	fc.kn = -1

	fc.dataset, err = fc.getDatasetInfo(dataset)

	return
}

func (fc *structuredContext) getAlgorithm(key, twk []byte) (
	alg structuredAlgorithm, err error) {
	if fc.dataset.Algorithm == "FF1" {
		alg, err = structured.NewFF1(
			key, twk,
			fc.dataset.TweakLengthMin, fc.dataset.TweakLengthMax,
			fc.dataset.InputAlphabet.Len(),
			fc.dataset.InputCharacterSet)
	} else {
		err = errors.New("unsupported algorithm: " + fc.dataset.Algorithm)
	}

	return
}

// retrieve algorithm and key information from the server
//
// for encryption this can be done right away as the key number is
// unknown. for decryption, it can't be done until the ciphertext
// has been presented and the key number decoded from it
func (fc *structuredContext) setAlgorithm(kn int) (err error) {
	var twk []byte
	var key structuredKey

	twk, err = base64.StdEncoding.DecodeString(fc.dataset.Tweak)
	if err != nil {
		return
	}

	key, err = fc.getKey(kn)
	if err != nil {
		return
	}

	fc.algo, err = fc.getAlgorithm(key.key, twk)
	if err == nil {
		fc.kn = key.num
	}

	return
}

// Create a new format preserving encryption object. The returned object
// can be reused to encrypt multiple plaintexts using the format (and
// algorithm and key) named by @dataset
func NewStructuredEncryption(c Credentials, dataset string) (*StructuredEncryption, error) {
	fc, err := newStructuredContext(c, dataset)
	if err == nil {
		err = fc.setAlgorithm(-1)
	}
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host)
	}
	return (*StructuredEncryption)(fc), err
}

// Encrypt a plaintext string using the key, algorithm, and format
// preserving parameters defined by the encryption object.
//
// @twk may be nil, in which case, the default will be used
func (fe *StructuredEncryption) Cipher(pt string, twk []byte) (
	ct string, err error) {
	var dataset *datasetInfo = &fe.dataset

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

	ctr, err = fe.algo.EncryptRunes(ptr, twk)
	if err != nil {
		return
	}

	fe.tracking.AddEvent(
		fe.papi, dataset.Name, "",
		trackingActionEncrypt,
		1, fe.kn)

	ctr = convertRadix(ctr, &dataset.InputAlphabet, &dataset.OutputAlphabet)
	ctr = encodeKeyNumber(
		ctr, &dataset.OutputAlphabet, fe.kn, dataset.NumEncodingBits)
	ctr, err = formatOutput(fmtr, ctr, &dataset.PassthroughAlphabet, rules)

	return string(ctr), err
}

// Encrypt a plaintext string using algorithm, format
// preserving parameters, and all keys defined by the
// encryption object.
//
// @twk may be nil, in which case, the default will be used
func (fe *StructuredEncryption) CipherForSearch(pt string, twk []byte) (
	ct []string, err error) {
	var dataset *datasetInfo = &fe.dataset
	var fmtr, ptr, ctr []rune
	var rules []passthroughRule

	deftwk, err := base64.StdEncoding.DecodeString(fe.dataset.Tweak)
	if err != nil {
		return
	}

	keys, err := ((*structuredContext)(fe)).getAllKeys()
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

		alg, err = ((*structuredContext)(fe)).getAlgorithm(keys[i].key, deftwk)
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
}

// Attach metadata to usage information reported by the application.
func (fe *StructuredEncryption) AddUserDefinedMetadata(data string) error {
	return fe.tracking.AddUserDefinedMetadata(data)
}

// Create a new format preserving decryption object. The returned object
// can be reused to decrypt multiple ciphertexts using the format (and
// algorithm and key) named by @dataset
func NewStructuredDecryption(c Credentials, dataset string) (*StructuredDecryption, error) {
	fc, err := newStructuredContext(c, dataset)
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host)
	}
	return (*StructuredDecryption)(fc), err
}

// Decrypt a ciphertext string using the key, algorithm, and format
// preserving parameters defined by the decryption object.
//
// @twk may be nil, in which case, the default will be used. Regardless,
// the tweak must match the one used during encryption of the plaintext
func (fd *StructuredDecryption) Cipher(ct string, twk []byte) (
	pt string, err error) {
	var dataset *datasetInfo = &fd.dataset

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
	if kn != fd.kn {
		err = (*structuredContext)(fd).setAlgorithm(kn)
		if err != nil {
			return
		}
	}

	ctr = convertRadix(ctr, &dataset.OutputAlphabet, &dataset.InputAlphabet)

	ptr, err := fd.algo.DecryptRunes(ctr, twk)
	if err != nil {
		return
	}

	fd.tracking.AddEvent(
		fd.papi, dataset.Name, "",
		trackingActionDecrypt,
		1, fd.kn)

	ptr, err = formatOutput(fmtr, ptr, &dataset.PassthroughAlphabet, rules)

	return string(ptr), err
}

func (fd *StructuredDecryption) Close() {
	fd.tracking.Close()
}

// Attach metadata to usage information reported by the application.
func (fd *StructuredDecryption) AddUserDefinedMetadata(data string) error {
	return fd.tracking.AddUserDefinedMetadata(data)
}

// StructuredEncrypt performs a format preserving encryption of a plaintext using
// the supplied credentials and according to the format named by @dataset
//
// @twk may be nil, in which case, the default will be used
//
// Upon success, error is nil, and the ciphertext is returned. If an
// error occurs, it will be indicated by the error return value.
func StructuredEncrypt(c Credentials, dataset, pt string, twk []byte) (string, error) {
	var ct string

	enc, err := NewStructuredEncryption(c, dataset)
	if err == nil {
		defer enc.Close()
		ct, err = enc.Cipher(pt, twk)
	}

	return ct, err
}

// StructuredEncrypt performs a format preserving encryption of a plaintext using
// the supplied credentials and according to the format named by @dataset, using
// all keys associated with that format
//
// @twk may be nil, in which case, the default will be used
//
// Upon success, error is nil, and the ciphertexts are returned. If an
// error occurs, it will be indicated by the error return value.
func StructuredEncryptForSearch(c Credentials, dataset, pt string, twk []byte) (
	[]string, error) {
	var ct []string

	enc, err := NewStructuredEncryption(c, dataset)
	if err == nil {
		defer enc.Close()
		ct, err = enc.CipherForSearch(pt, twk)
	}

	return ct, err
}

// StructuredDecrypt performs a format preserving decryption of a ciphertext.
// The credentials must be associated with the key used to encrypt
// the ciphertext.
//
// @dataset is the name of the format used to encrypt the data
// @twk may be nil, in which case, the default will be used. In either
// case it must match that used during encryption
//
// Upon success, error is nil, and the plaintext is returned. If an
// error occurs, it will be indicated by the error return value.
func StructuredDecrypt(c Credentials, dataset, ct string, twk []byte) (string, error) {
	var pt string

	dec, err := NewStructuredDecryption(c, dataset)
	if err == nil {
		defer dec.Close()
		pt, err = dec.Cipher(ct, twk)
	}

	return pt, err
}
