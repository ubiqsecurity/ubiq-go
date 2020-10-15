package main

import (
	"gitlab.com/ubiqsecurity/ubiq-go"
	"io"
	"os"
)

func simpleEncrypt(c ubiq.Credentials, ifp, ofp *os.File, size int64) error {
	pt := make([]byte, size)

	// read the whole file
	_, err := ifp.Read(pt)
	if err == nil {
		var ct []byte

		// encrypt the whole file
		ct, err = ubiq.Encrypt(c, pt)
		if err == nil {
			// write the whole file
			_, err = ofp.Write(ct)
		}
	}

	return err
}

func piecewiseEncrypt(c ubiq.Credentials, ifp, ofp *os.File) error {
	var pt, ct []byte = make([]byte, 128*1024), []byte{}

	// new encryption object
	enc, err := ubiq.NewEncryption(c, 1)
	if err != nil {
		return err
	}
	defer enc.Close()

	// start the new encryption and write out
	// any cipher text produced
	ct, err = enc.Begin()
	if err != nil {
		return err
	}
	_, err = ofp.Write(ct)

	// read chunks of data and encrypt them,
	// writing the results to the output file
	for err == nil {
		var n int

		n, err = ifp.Read(pt)
		if err == nil {
			ct, err = enc.Update(pt[:n])
			if err == nil {
				_, err = ofp.Write(ct)
			}
		} else if err == io.EOF {
			err = nil
			break
		}
	}

	// finalize the encryption, writing any
	// remaining cipher text to the output file
	if err == nil {
		ct, err = enc.End()
		if err == nil {
			_, err = ofp.Write(ct)
		}
	}

	return err
}
