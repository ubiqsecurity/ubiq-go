package ubiq

// Deprecated: Replaced by datasetInfo
type ffsInfo datasetInfo

// Deprecated: Replaced by structuredAlgorithm
type fpeAlgorithm structuredAlgorithm

// Deprecated: Replaced by structuredContext
type fpeContext structuredContext

// Deprecated: Replaced by structuredKey
type fpeKey structuredKey

// Deprecated: Replaced by StructuredEncryption
type FPEncryption StructuredEncryption

// Deprecated: Replaced by StructuredDecryption
type FPDecryption StructuredEncryption

// Deprecated: Replaced by fetchDataset
func (fc *fpeContext) getFFSInfo(name string) (ffs ffsInfo, err error) {
	info, err := ((*structuredContext)(fc)).fetchDataset(name)
	return ffsInfo(info), err
}

func newFPEContext(c Credentials, ffs string) (fc *fpeContext, err error) {

	sC, err := newStructuredContext(c)
	if err != nil {
		return &fpeContext{}, err
	}

	sC.dataset, err = sC.fetchDataset(ffs)
	fpeC := fpeContext(*sC)
	fc = &fpeC
	return
}

// Deprecated: NewFPEncryption exists for historical compatibility and should
// not be used. Instead use `enc, err := NewStructuredEncryption(creds)`
// to create a context, and then `enc.Cipher(plaintext, datasetName, tweak)` to encrypt.
func NewFPEncryption(c Credentials, ffs string) (*FPEncryption, error) {
	fc, err := newFPEContext(c, ffs)
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host, c.config)
	}
	fc.dataset, err = ((*structuredContext)(fc)).fetchDataset(ffs)
	return (*FPEncryption)(fc), err
}

// Encrypt a plaintext string using the key, algorithm, and format
// preserving parameters defined by the encryption object.
//
// @twk may be nil, in which case, the default will be used
//
// Deprecated: FPEncryption.Cipher exists for historical compatibility and should
// not be used. Please use StructuredDecryption and associated methods instead.
func (fd *FPEncryption) Cipher(pt string, twk []byte) (ct string, err error) {
	return ((*StructuredEncryption)(fd)).Cipher(pt, fd.dataset.Name, twk)
}

// Create a new format preserving decryption object. The returned object
// can be reused to decrypt multiple ciphertexts using the format (and
// algorithm and key) named by @ffs
//
// Deprecated: NewFPDecryption exists for historical compatibility and should
// not be used. Instead use `dec, err := NewStructuredDecryption(creds)`
// to create a context, and then `dec.Cipher(plaintext, datasetName, tweak)` to decrypt.
func NewFPDecryption(c Credentials, ffs string) (*FPDecryption, error) {
	fc, err := newFPEContext(c, ffs)
	if err == nil {
		fc.tracking = newTrackingContext(fc.client, fc.host, c.config)
	}
	fc.dataset, err = ((*structuredContext)(fc)).fetchDataset(ffs)
	return (*FPDecryption)(fc), err
}

// Decrypt a ciphertext string using the key, algorithm, and format
// preserving parameters defined by the decryption object.
//
// @twk may be nil, in which case, the default will be used. Regardless,
// the tweak must match the one used during encryption of the plaintext
//
// Deprecated: FPDecryption.Cipher exists for historical compatibility and should
// not be used. Please use StructuredDecryption and associated methods instead.
func (fd *FPDecryption) Cipher(ct string, twk []byte) (pt string, err error) {
	return ((*StructuredDecryption)(fd)).Cipher(ct, fd.dataset.Name, twk)
}

// Deprecated: Please use StructuredEncryption objects instead.
func (fe *FPEncryption) Close() {
	fe.tracking.Close()
}

// Deprecated: Please use StructuredDecryption objects instead.
func (fd *FPDecryption) Close() {
	fd.tracking.Close()
}

// FPEncrypt performs a format preserving encryption of a plaintext using
// the supplied credentials and according to the format named by @ffs, using
// all keys associated with that format
//
// @twk may be nil, in which case, the default will be used
//
// Upon success, error is nil, and the ciphertext is returned. If an
// error occurs, it will be indicated by the error return value.
//
// Deprecated: Simple Encrypt/Decrypt exists for historical compatibility and should
// not be used. Instead use `enc, err := NewStructuredEncryption(creds)`
// to create a context, and then `enc.Cipher(plaintext, datasetName, tweak)` to encrypt.
func FPEncrypt(c Credentials, ffs, pt string, twk []byte) (string, error) {
	var ct string
	enc, err := NewStructuredEncryption(c)
	if err == nil {
		defer enc.Close()
		ct, err = enc.Cipher(ffs, pt, twk)
	}
	return ct, err
}

// FPEncryptForSearch performs a format preserving encryption of a plaintext using
// the supplied credentials and according to the format named by @ffs, using
// all keys associated with that format
//
// @twk may be nil, in which case, the default will be used
//
// Upon success, error is nil, and the ciphertexts are returned. If an
// error occurs, it will be indicated by the error return value.
//
// Deprecated: Simple Encrypt/Decrypt exists for historical compatibility and should
// not be used. Instead use `enc, err := NewStructuredEncryption(creds)`
// to create a context, and then `enc.CipherForSearch(plaintext, datasetName, tweak)` to encrypt.
func FPEncryptForSearch(c Credentials, ffs, pt string, twk []byte) ([]string, error) {
	var ct []string

	enc, err := NewStructuredEncryption(c)
	if err == nil {
		defer enc.Close()
		ct, err = enc.CipherForSearch(ffs, pt, twk)
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
//
// Deprecated: Simple Encrypt/Decrypt exists for historical compatibility and should
// not be used. Instead use `enc, err := NewStructuredEncryption(creds)`
// to create a context, and then `enc.Cipher(plaintext, datasetName, tweak)` to encrypt.
func FPDecrypt(c Credentials, ffs, pt string, twk []byte) (string, error) {
	var ct string

	enc, err := NewStructuredDecryption(c)
	if err == nil {
		defer enc.Close()
		ct, err = enc.Cipher(ffs, pt, twk)
	}
	return ct, err
}

func (sC *structuredContext) getDatasetInfo(dataset string) (datasetInfo, error) {
	return sC.fetchDataset(dataset)
}
