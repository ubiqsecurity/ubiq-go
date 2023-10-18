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
	PassthroughAlphabet     algo.Alphabet
	OutputCharacterSet      string `json:"output_character_set"`
	OutputAlphabet          algo.Alphabet
	InputCharacterSet       string `json:"input_character_set"`
	InputAlphabet           algo.Alphabet
	InputLengthMin          int    `json:"min_input_length"`
	InputLengthMax          int    `json:"max_input_length"`
	NumEncodingBits         int    `json:"msb_encoding_bits"`
	Salt                    string `json:"salt"`
	Tweak                   string `json:"tweak"`
	TweakLengthMax          int    `json:"tweak_max_len"`
	TweakLengthMin          int    `json:"tweak_min_len"`
	TweakSource             string `json:"tweak_source"`
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
	ffs *ffsInfo

	// the key number and algorithm
	// a key number of -1 indicates that the key
	// number and algorithm are not set
	kn   int
	algo fpeAlgorithm

	tracking trackingContext
}

// Reusable object to preserve context across
// multiple encryptions using the same format
type FPEncryption fpeContext

// Reusable object to preserve context across
// multiple decryptions using the same format
type FPDecryption fpeContext

// convert a string representation of a number (@inp) in the radix/alphabet
// described by @ics to the radix/alphabet described by @ocs
func convertRadix(inp []rune, ics, ocs *algo.Alphabet) []rune {
	var n *big.Int = big.NewInt(0)
	return algo.BigIntToRunes(ocs,
		algo.RunesToBigInt(n, ics, inp), len(inp))
}

// remove passthrough characters from the input and preserve the format
// so the output can be reformatted after encryption/decryption
func formatInput(inp []rune, pth, icr *algo.Alphabet, ocr0 rune) (fmtr, out []rune, err error) {
	fmtr = make([]rune, 0, len(inp))
	out = make([]rune, 0, len(inp))

	for _, c := range inp {
		if icr.PosOf(c) >= 0 {
			fmtr = append(fmtr, ocr0)
			out = append(out, c)
		} else if pth.PosOf(c) >= 0 {
			fmtr = append(fmtr, c)
		} else {
			err = errors.New("invalid input character")
		}
	}

	return
}

// reinsert passthrough characters into output
func formatOutput(fmtr, inp []rune, ocr0 rune) (out []rune, err error) {
	out = make([]rune, 0, len(fmtr))

	for _, c := range fmtr {
		if c == ocr0 {
			out = append(out, inp[0])
			inp = inp[1:]
		} else {
			out = append(out, c)
		}
	}

	if len(inp) > 0 {
		err = errors.New("mismatched format and output strings")
	}

	return
}

// encode the key number into a ciphertext
func encodeKeyNumber(inp []rune, ocs *algo.Alphabet, n, sft int) []rune {
	idx := ocs.PosOf(inp[0])
	idx += n << sft

	inp[0] = ocs.ValAt(idx)
	return inp
}

// recover the key number from a ciphertext
func decodeKeyNumber(inp []rune, ocs *algo.Alphabet, sft int) ([]rune, int) {
	c := ocs.PosOf(inp[0])
	n := c >> sft

	inp[0] = ocs.ValAt(c - (n << sft))
	return inp, n
}

// retrieve the format information from the server
func getFFSInfo(client *httpClient, host, papi, name string) (ffs *ffsInfo, err error) {
	var query = "ffs_name=" + url.QueryEscape(name) + "&" +
		"papi=" + url.QueryEscape(papi)

	var rsp *http.Response

	rsp, err = client.Get(host + "/api/v0/ffs?" + query)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusOK {
		ffs = new(ffsInfo)
		err = json.NewDecoder(rsp.Body).Decode(ffs)
	} else {
		err = errors.New("unexpected response: " + rsp.Status)
	}

	if err == nil {
		// convert the character string to arrays of runes
		// to enable unicode handling
		ffs.PassthroughAlphabet, _ =
			algo.NewAlphabet(ffs.PassthroughCharacterSet)
		ffs.OutputAlphabet, _ =
			algo.NewAlphabet(ffs.OutputCharacterSet)
		ffs.InputAlphabet, _ =
			algo.NewAlphabet(ffs.InputCharacterSet)
	}

	return ffs, err
}

// retrieve the key from the server
func getKey(client *httpClient, host, papi, srsa, name string, kn int) (
	key []byte, num int, err error) {
	var query = "ffs_name=" + url.QueryEscape(name) + "&" +
		"papi=" + url.QueryEscape(papi)

	var rsp *http.Response
	var obj struct {
		EPK string `json:"encrypted_private_key"`
		WDK string `json:"wrapped_data_key"`
		Num string `json:"key_number"`
	}

	if kn >= 0 {
		query += "&key_number=" + strconv.Itoa(kn)
	}

	rsp, err = client.Get(host + "/api/v0/fpe/key?" + query)
	if err != nil {
		return
	}
	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusOK {
		err = json.NewDecoder(rsp.Body).Decode(&obj)
	} else {
		err = errors.New("unexpected response: " + rsp.Status)
	}

	if err == nil {
		num, _ = strconv.Atoi(obj.Num)
		key, err = unwrapDataKey(obj.WDK, obj.EPK, srsa)
	}

	return
}

func newFPEContext(c Credentials, ffs string) (this *fpeContext, err error) {
	this = new(fpeContext)

	this.client = newHttpClient(c)

	this.host, _ = c.host()
	this.papi, _ = c.papi()
	this.srsa, _ = c.srsa()

	this.kn = -1

	this.ffs, err = getFFSInfo(&this.client, this.host, this.papi, ffs)

	return
}

// retrieve algorithm and key information from the server
//
// for encryption this can be done right away as the key number is
// unknown. for decryption, it can't be done until the ciphertext
// has been presented and the key number decoded from it
func (this *fpeContext) setAlgorithm(kn int) (err error) {
	var key, twk []byte

	twk, err = base64.StdEncoding.DecodeString(this.ffs.Tweak)
	if err != nil {
		return
	}

	key, kn, err = getKey(&this.client,
		this.host, this.papi, this.srsa,
		this.ffs.Name, kn)
	if err != nil {
		return
	}

	if this.ffs.Algorithm == "FF1" {
		this.algo, err = algo.NewFF1(
			key, twk,
			this.ffs.TweakLengthMin, this.ffs.TweakLengthMax,
			this.ffs.InputAlphabet.Len(),
			this.ffs.InputCharacterSet)
	} else {
		err = errors.New("unsupported algorithm: " + this.ffs.Algorithm)
	}

	if err == nil {
		this.kn = kn
	}

	return
}

// Create a new format preserving encryption object. The returned object
// can be reused to encrypt multiple plaintexts using the format (and
// algorithm and key) named by @ffs
func NewFPEncryption(c Credentials, ffs string) (*FPEncryption, error) {
	this, err := newFPEContext(c, ffs)
	if err == nil {
		err = this.setAlgorithm(-1)
	}
	if err == nil {
		this.tracking = newTrackingContext(this.client, this.host)
	}
	return (*FPEncryption)(this), err
}

// Encrypt a plaintext string using the key, algorithm, and format
// preserving parameters defined by the encryption object.
//
// @twk may be nil, in which case, the default will be used
func (this *FPEncryption) Cipher(pt string, twk []byte) (
	ct string, err error) {
	var ffs *ffsInfo = this.ffs

	var fmtr, ptr, ctr []rune

	fmtr, ptr, err = formatInput(
		[]rune(pt),
		&ffs.PassthroughAlphabet,
		&ffs.InputAlphabet,
		ffs.OutputAlphabet.ValAt(0))
	if err != nil {
		return
	}

	if len(ptr) < ffs.InputLengthMin || len(ptr) > ffs.InputLengthMax {
		err = errors.New("input length out of bounds")
		return
	}

	ctr, err = this.algo.EncryptRunes(ptr, twk)
	if err != nil {
		return
	}

	this.tracking.AddEvent(
		this.papi, ffs.Name, "",
		trackingActionEncrypt,
		1, this.kn)

	ctr = convertRadix(ctr, &ffs.InputAlphabet, &ffs.OutputAlphabet)
	ctr = encodeKeyNumber(
		ctr, &ffs.OutputAlphabet, this.kn, ffs.NumEncodingBits)
	ctr, err = formatOutput(fmtr, ctr, ffs.OutputAlphabet.ValAt(0))
	return string(ctr), err
}

func (this *FPEncryption) Close() {
	this.tracking.Close()
}

// Create a new format preserving decryption object. The returned object
// can be reused to decrypt multiple ciphertexts using the format (and
// algorithm and key) named by @ffs
func NewFPDecryption(c Credentials, ffs string) (*FPDecryption, error) {
	this, err := newFPEContext(c, ffs)
	if err == nil {
		this.tracking = newTrackingContext(this.client, this.host)
	}
	return (*FPDecryption)(this), err
}

// Decrypt a ciphertext string using the key, algorithm, and format
// preserving parameters defined by the decryption object.
//
// @twk may be nil, in which case, the default will be used. Regardless,
// the tweak must match the one used during encryption of the plaintext
func (this *FPDecryption) Cipher(ct string, twk []byte) (
	pt string, err error) {
	var ffs *ffsInfo = this.ffs

	var fmtr, ctr []rune
	var kn int

	fmtr, ctr, err = formatInput(
		[]rune(ct),
		&ffs.PassthroughAlphabet,
		&ffs.OutputAlphabet,
		ffs.InputAlphabet.ValAt(0))
	if err != nil {
		return
	}

	ctr, kn = decodeKeyNumber(ctr, &ffs.OutputAlphabet, ffs.NumEncodingBits)
	if kn != this.kn {
		err = (*fpeContext)(this).setAlgorithm(kn)
		if err != nil {
			return
		}
	}

	ctr = convertRadix(ctr, &ffs.OutputAlphabet, &ffs.InputAlphabet)

	ptr, err := this.algo.DecryptRunes(ctr, twk)
	if err != nil {
		return
	}

	this.tracking.AddEvent(
		this.papi, ffs.Name, "",
		trackingActionDecrypt,
		1, this.kn)

	ptr, err = formatOutput(fmtr, ptr, ffs.InputAlphabet.ValAt(0))
	return string(ptr), err
}

func (this *FPDecryption) Close() {
	this.tracking.Close()
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
