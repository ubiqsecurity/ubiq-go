package ubiq

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strconv"

	algo "gitlab.com/ubiqsecurity/ubiq-fpe-go"
)

type ffsInfo struct {
	Name                    string `json:"name"`
	Type                    string `json:"fpe_definable_type"`
	Algorithm               string `json:"encryption_algorithm"`
	PassthroughCharacterSet string `json:"passthrough"`
	PassthroughRuneSet      []rune
	OutputCharacterSet      string `json:"output_character_set"`
	OutputRuneSet           []rune
	InputCharacterSet       string `json:"input_character_set"`
	InputRuneSet            []rune
	InputLengthMin          int    `json:"min_input_length"`
	InputLengthMax          int    `json:"max_input_length"`
	NumEncodingBits         int    `json:"msb_encoding_bits"`
	Salt                    string `json:"salt"`
	Tweak                   string `json:"tweak"`
	TweakLengthMax          int    `json:"tweak_max_len"`
	TweakLengthMin          int    `json:"tweak_min_len"`
	TweakSource             string `json:"tweak_source"`
}

type defKeys struct {
	CurrentKeyNum       int      `json:"current_key_number"`
	EncryptedPrivateKey string   `json:"encrypted_private_key"`
	FFS                 ffsInfo  `json:"ffs"`
	EncryptedDataKeys   []string `json:"keys"`
	Retrieved           float32  `json:"retrieved"`
}

// this interface was created so that it could be placed into
// the fpeContext so that fpeContext could be used in both encryption
// and decryption operations
//
// its a convenience for this code and should follow whatever interfaces
// are provided by the underlying library rather than dictating what
// the underlying library should look like/present
type fpeAlgorithm interface {
	// the encrypt and decrypt interfaces aren't used because,
	// internally, it's easier to deal with runes and avoid the
	// back and forth conversions to strings
	Encrypt(string, []byte) (string, error)
	Decrypt(string, []byte) (string, error)

	EncryptRunes([]rune, []byte) ([]rune, error)
	DecryptRunes([]rune, []byte) ([]rune, error)
}

type fpeContext struct {
	// object/data for dealing with the server
	client           httpClient
	host, papi, srsa string

	// information about the format of the data
	ffs ffsInfo

	// the key number and algorithm
	// a key number of -1 indicates that the key
	// number and algorithm are not set
	kn   int
	algo fpeAlgorithm

	tracking trackingContext
}

type fpeKey struct {
	num int
	key []byte
}

// Reusable object to preserve context across
// multiple encryptions using the same format
type FPEncryption fpeContext

// Reusable object to preserve context across
// multiple decryptions using the same format
type FPDecryption fpeContext

// ffsCache is indexed first by the public api key and then
// by the format name. objects in the map(s) are stored as
// pointers to reduce the expense of fetching them, and also
// so that they can be updated in place.
var ffsCache map[string]*map[string]*ffsInfo

func fetchFFS(client *httpClient, host, papi, name string) (ffsInfo, error) {
	var err error
	var ok bool

	if ffsCache == nil {
		ffsCache = make(map[string]*map[string]*ffsInfo)
	}

	if _, ok = ffsCache[papi]; !ok {
		m := make(map[string]*ffsInfo)
		ffsCache[papi] = &m
	}

	if _, ok = (*ffsCache[papi])[name]; !ok {
		var query = "ffs_name=" + url.QueryEscape(name) + "&" +
			"papi=" + url.QueryEscape(papi)

		var rsp *http.Response
		var ffs *ffsInfo

		rsp, err = client.Get(host + "/api/v0/ffs?" + query)
		if err != nil {
			return ffsInfo{}, err
		}
		defer rsp.Body.Close()

		if rsp.StatusCode == http.StatusOK {
			ffs = new(ffsInfo)
			err = json.NewDecoder(rsp.Body).Decode(ffs)
		} else {
			err = errors.New("unexpected response: " + rsp.Status)
		}
		if err != nil {
			return ffsInfo{}, err
		}

		// convert the character string to arrays of runes
		// to enable unicode handling
		ffs.PassthroughRuneSet = []rune(ffs.PassthroughCharacterSet)
		ffs.OutputRuneSet = []rune(ffs.OutputCharacterSet)
		ffs.InputRuneSet = []rune(ffs.InputCharacterSet)

		(*ffsCache[papi])[name] = ffs
	}

	return *(*ffsCache[papi])[name], nil
}

func flushFFS(papi, name *string) {
	if ffsCache == nil {
		ffsCache = make(map[string]*map[string]*ffsInfo)
	}

	if papi == nil {
		ffsCache = make(map[string]*map[string]*ffsInfo)
	} else if m, ok := ffsCache[*papi]; ok {
		if name == nil {
			delete(ffsCache, *papi)
		} else if _, ok := (*m)[*name]; ok {
			delete(*m, *name)
		}
	}
}

// keyCache is indexed by public api, then by the format name,
// and finally by the key number. items in the map are pointers
// to allow updating in place and more efficient fetching (e.g.
// pointers instead of copies of the objects)
var keyCache map[string](*map[string](*map[int]*fpeKey))

func fetchKey(client *httpClient, host, papi, srsa, name string, n int) (
	fpeKey, error) {
	var ok bool
	var err error

	if keyCache == nil {
		keyCache = make(map[string](*map[string](*map[int]*fpeKey)))
	}
	if _, ok = keyCache[papi]; !ok {
		m := make(map[string](*map[int]*fpeKey))
		keyCache[papi] = &m
	}
	if _, ok = (*keyCache[papi])[name]; !ok {
		m := make(map[int]*fpeKey)
		(*keyCache[papi])[name] = &m
	}

	if _, ok = (*(*keyCache[papi])[name])[n]; !ok {
		var query = "ffs_name=" + url.QueryEscape(name) + "&" +
			"papi=" + url.QueryEscape(papi)

		var key fpeKey
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
			return fpeKey{}, err
		}
		defer rsp.Body.Close()

		if rsp.StatusCode == http.StatusOK {
			err = json.NewDecoder(rsp.Body).Decode(&obj)
		} else {
			err = errors.New("unexpected response: " + rsp.Status)
		}
		if err != nil {
			return fpeKey{}, err
		}

		key.num, _ = strconv.Atoi(obj.Num)
		key.key, err = unwrapDataKey(obj.WDK, obj.EPK, srsa)
		if err != nil {
			return fpeKey{}, err
		}

		(*(*keyCache[papi])[name])[key.num] = &key
		if n < 0 {
			(*(*keyCache[papi])[name])[-1] = &key
		}
	}

	return *(*(*keyCache[papi])[name])[n], nil
}

func fetchAllKeys(client *httpClient, host, papi, srsa, name string) (
	keys []fpeKey, err error) {
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
		keyCache = make(map[string](*map[string](*map[int]*fpeKey)))
	}
	if _, ok = keyCache[papi]; !ok {
		m := make(map[string](*map[int]*fpeKey))
		keyCache[papi] = &m
	}
	if _, ok = (*keyCache[papi])[name]; !ok {
		m := make(map[int]*fpeKey)
		(*keyCache[papi])[name] = &m
	}

	keys = make([]fpeKey, len(js[name].EncryptedDataKeys))
	for i := range js[name].EncryptedDataKeys {
		if _, ok := (*(*keyCache[papi])[name])[i]; !ok {
			var key fpeKey

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
		keyCache = make(map[string](*map[string](*map[int]*fpeKey)))
	}
	if papi == nil {
		keyCache = make(map[string](*map[string](*map[int]*fpeKey)))
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

// find the first occurrence of a rune in an array/slice
//
// i hate the inefficiency of this function, especially given
// how often it is (expected to be) called. one idea is to sort it
// and store the rune and its original position so that a binary
// search can be performed. this could be done with a map, too. it
// probably doesn't make sense to build out that data structure
// unless a large number of encryptions/decryptions are being
// performed
func findRune(rs []rune, r rune) int {
	for i := range rs {
		if rs[i] == r {
			return i
		}
	}

	return -1
}

// convert a string representation of a number (@inp) in the radix/alphabet
// described by @ics to the radix/alphabet described by @ocs
func convertRadix(inp, ics, ocs []rune) []rune {
	var n *big.Int = big.NewInt(0)
	return algo.BigIntToRunes(len(ocs), ocs,
		algo.RunesToBigInt(n, len(ics), ics, inp), len(inp))
}

// remove passthrough characters from the input and preserve the format
// so the output can be reformatted after encryption/decryption
func formatInput(inp, pth, icr, ocr []rune) (fmtr, out []rune, err error) {
	for _, c := range inp {
		if findRune(pth, c) >= 0 {
			fmtr = append(fmtr, c)
		} else {
			fmtr = append(fmtr, ocr[0])

			if findRune(icr, c) >= 0 {
				out = append(out, c)
			} else {
				err = errors.New("invalid input character")
			}
		}
	}

	return
}

// reinsert passthrough characters into output
func formatOutput(fmtr, inp, pth []rune) (out []rune, err error) {
	for _, c := range fmtr {
		if findRune(pth, c) >= 0 {
			out = append(out, c)
		} else {
			out = append(out, inp[0])
			inp = inp[1:]
		}
	}

	if len(inp) > 0 {
		err = errors.New("mismatched format and output strings")
	}

	return
}

// encode the key number into a ciphertext
func encodeKeyNumber(inp, ocs []rune, n, sft int) []rune {
	idx := findRune(ocs, inp[0])
	idx += n << sft

	inp[0] = ocs[idx]
	return inp
}

// recover the key number from a ciphertext
func decodeKeyNumber(inp, ocs []rune, sft int) ([]rune, int) {
	c := findRune(ocs, inp[0])
	n := c >> sft

	inp[0] = ocs[c-(n<<sft)]
	return inp, n
}

// retrieve the format information from the server
func (fc *fpeContext) getFFSInfo(name string) (ffs ffsInfo, err error) {
	return fetchFFS(&fc.client, fc.host, fc.papi, name)
}

// retrieve the key from the server
func (fc *fpeContext) getKey(kn int) (key fpeKey, err error) {
	return fetchKey(&fc.client,
		fc.host, fc.papi, fc.srsa,
		fc.ffs.Name, kn)
}

func (fc *fpeContext) getAllKeys() (keys []fpeKey, err error) {
	return fetchAllKeys(&fc.client,
		fc.host, fc.papi, fc.srsa,
		fc.ffs.Name)
}

func newFPEContext(c Credentials, ffs string) (fc *fpeContext, err error) {
	fc = new(fpeContext)

	fc.client = newHttpClient(c)

	fc.host, _ = c.host()
	fc.papi, _ = c.papi()
	fc.srsa, _ = c.srsa()

	fc.kn = -1

	fc.ffs, err = fc.getFFSInfo(ffs)

	return
}

func (fc *fpeContext) getAlgorithm(key, twk []byte) (
	alg fpeAlgorithm, err error) {
	if fc.ffs.Algorithm == "FF1" {
		alg, err = algo.NewFF1(
			key, twk,
			fc.ffs.TweakLengthMin, fc.ffs.TweakLengthMax,
			len(fc.ffs.InputRuneSet), fc.ffs.InputCharacterSet)
	} else {
		err = errors.New("unsupported algorithm: " + fc.ffs.Algorithm)
	}

	return
}

// retrieve algorithm and key information from the server
//
// for encryption this can be done right away as the key number is
// unknown. for decryption, it can't be done until the ciphertext
// has been presented and the key number decoded from it
func (fc *fpeContext) setAlgorithm(kn int) (err error) {
	var twk []byte
	var key fpeKey

	twk, err = base64.StdEncoding.DecodeString(fc.ffs.Tweak)
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
// algorithm and key) named by @ffs
func NewFPEncryption(c Credentials, ffs string) (*FPEncryption, error) {
	fc, err := newFPEContext(c, ffs)
	if err == nil {
		err = fc.setAlgorithm(-1)
	}
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host)
	}
	return (*FPEncryption)(fc), err
}

// Encrypt a plaintext string using the key, algorithm, and format
// preserving parameters defined by the encryption object.
//
// @twk may be nil, in which case, the default will be used
func (fe *FPEncryption) Cipher(pt string, twk []byte) (
	ct string, err error) {
	var ffs *ffsInfo = &fe.ffs

	var fmtr, ptr, ctr []rune

	fmtr, ptr, err = formatInput(
		[]rune(pt),
		ffs.PassthroughRuneSet, ffs.InputRuneSet, ffs.OutputRuneSet)
	if err != nil {
		return
	}

	if len(ptr) < ffs.InputLengthMin || len(ptr) > ffs.InputLengthMax {
		err = errors.New("input length out of bounds")
		return
	}

	ctr, err = fe.algo.EncryptRunes(ptr, twk)
	if err != nil {
		return
	}

	fe.tracking.AddEvent(
		fe.papi, ffs.Name, "",
		trackingActionEncrypt,
		1, fe.kn)

	ctr = convertRadix(ctr, ffs.InputRuneSet, ffs.OutputRuneSet)
	ctr = encodeKeyNumber(
		ctr, ffs.OutputRuneSet, fe.kn, ffs.NumEncodingBits)
	ctr, err = formatOutput(fmtr, ctr, ffs.PassthroughRuneSet)

	return string(ctr), err
}

// Encrypt a plaintext string using algorithm, format
// preserving parameters, and all keys defined by the
// encryption object.
//
// @twk may be nil, in which case, the default will be used
func (fe *FPEncryption) CipherForSearch(pt string, twk []byte) (
	ct []string, err error) {
	var ffs *ffsInfo = &fe.ffs
	var fmtr, ptr, ctr []rune

	deftwk, err := base64.StdEncoding.DecodeString(fe.ffs.Tweak)
	if err != nil {
		return
	}

	keys, err := ((*fpeContext)(fe)).getAllKeys()
	if err != nil {
		return
	}

	fmtr, ptr, err = formatInput([]rune(pt), ffs.PassthroughRuneSet, ffs.InputRuneSet, ffs.OutputRuneSet)
	if err != nil {
		return
	}
	if len(ptr) < ffs.InputLengthMin || len(ptr) > ffs.InputLengthMax {
		err = errors.New("input length out of bounds")
		return
	}

	ct = make([]string, len(keys))
	_ptr := make([]rune, len(ptr))
	for i := range keys {
		var alg fpeAlgorithm

		alg, err = ((*fpeContext)(fe)).getAlgorithm(keys[i].key, deftwk)
		if err != nil {
			return
		}

		copy(_ptr, ptr)
		ctr, err = alg.EncryptRunes(_ptr, twk)
		if err != nil {
			return
		}

		fe.tracking.AddEvent(fe.papi, ffs.Name, "", trackingActionEncrypt, 1, i)

		ctr = convertRadix(ctr, ffs.InputRuneSet, ffs.OutputRuneSet)
		ctr = encodeKeyNumber(ctr, ffs.OutputRuneSet, i, ffs.NumEncodingBits)
		ctr, err = formatOutput(fmtr, ctr, ffs.PassthroughRuneSet)
		if err != nil {
			return
		}

		ct[i] = string(ctr)
	}

	return
}

func (fe *FPEncryption) Close() {
	fe.tracking.Close()
}

// Create a new format preserving decryption object. The returned object
// can be reused to decrypt multiple ciphertexts using the format (and
// algorithm and key) named by @ffs
func NewFPDecryption(c Credentials, ffs string) (*FPDecryption, error) {
	fc, err := newFPEContext(c, ffs)
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host)
	}
	return (*FPDecryption)(fc), err
}

// Decrypt a ciphertext string using the key, algorithm, and format
// preserving parameters defined by the decryption object.
//
// @twk may be nil, in which case, the default will be used. Regardless,
// the tweak must match the one used during encryption of the plaintext
func (fd *FPDecryption) Cipher(ct string, twk []byte) (
	pt string, err error) {
	var ffs *ffsInfo = &fd.ffs

	var fmtr, ctr []rune
	var kn int

	fmtr, ctr, err = formatInput(
		[]rune(ct),
		ffs.PassthroughRuneSet, ffs.OutputRuneSet, ffs.InputRuneSet)
	if err != nil {
		return
	}

	ctr, kn = decodeKeyNumber(ctr, ffs.OutputRuneSet, ffs.NumEncodingBits)
	if kn != fd.kn {
		err = (*fpeContext)(fd).setAlgorithm(kn)
		if err != nil {
			return
		}
	}

	ctr = convertRadix(ctr, ffs.OutputRuneSet, ffs.InputRuneSet)

	ptr, err := fd.algo.DecryptRunes(ctr, twk)
	if err != nil {
		return
	}

	fd.tracking.AddEvent(
		fd.papi, ffs.Name, "",
		trackingActionDecrypt,
		1, fd.kn)

	ptr, err = formatOutput(fmtr, ptr, ffs.PassthroughRuneSet)
	return string(ptr), err
}

func (fd *FPDecryption) Close() {
	fd.tracking.Close()
}

// FPEncrypt performs a format preserving encryption of a plaintext using
// the supplied credentials and according to the format named by @ffs
//
// @twk may be nil, in which case, the default will be used
//
// Upon success, error is nil, and the ciphertext is returned. If an
// error occurs, it will be indicated by the error return value.
func FPEncrypt(c Credentials, ffs, pt string, twk []byte) (string, error) {
	var ct string

	enc, err := NewFPEncryption(c, ffs)
	if err == nil {
		defer enc.Close()
		ct, err = enc.Cipher(pt, twk)
	}

	return ct, err
}

// FPEncrypt performs a format preserving encryption of a plaintext using
// the supplied credentials and according to the format named by @ffs, using
// all keys associated with that format
//
// @twk may be nil, in which case, the default will be used
//
// Upon success, error is nil, and the ciphertexts are returned. If an
// error occurs, it will be indicated by the error return value.
func FPEncryptForSearch(c Credentials, ffs, pt string, twk []byte) (
	[]string, error) {
	var ct []string

	enc, err := NewFPEncryption(c, ffs)
	if err == nil {
		defer enc.Close()
		ct, err = enc.CipherForSearch(pt, twk)
	}

	return ct, err
}

// FPDecrypt performs a format preserving decryption of a ciphertext.
// The credentials must be associated with the key used to encrypt
// the ciphertext.
//
// @ffs is the name of the format used to encrypt the data
// @twk may be nil, in which case, the default will be used. In either
// case it must match that used during encryption
//
// Upon success, error is nil, and the plaintext is returned. If an
// error occurs, it will be indicated by the error return value.
func FPDecrypt(c Credentials, ffs, ct string, twk []byte) (string, error) {
	var pt string

	dec, err := NewFPDecryption(c, ffs)
	if err == nil {
		defer dec.Close()
		pt, err = dec.Cipher(ct, twk)
	}

	return pt, err
}
