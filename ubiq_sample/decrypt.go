// Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains the property
// of Ubiq Security, Inc. The intellectual and technical concepts contained
// herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
// covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this
// information or reproduction of this material is strictly forbidden
// unless prior written permission is obtained from Ubiq Security, Inc.
//
// Your use of the software is expressly conditioned upon the terms
// and conditions available at:
//
//     https://ubiqsecurity.com/legal

package main

import (
	"gitlab.com/ubiqsecurity/ubiq-go"
	"io"
	"os"
)

func simpleDecrypt(c ubiq.Credentials, ifp, ofp *os.File, size int64) error {
	ct := make([]byte, size)

	// read the whole file
	_, err := ifp.Read(ct)
	if err == nil {
		var pt []byte

		// decrypt the whole file
		pt, err = ubiq.Decrypt(c, ct)
		if err == nil {
			// write the whole file
			_, err = ofp.Write(pt)
		}
	}

	return err
}

func piecewiseDecrypt(c ubiq.Credentials, ifp, ofp *os.File) error {
	var ct, pt []byte = make([]byte, 128*1024), []byte{}

	// new decryption object
	dec, err := ubiq.NewDecryption(c)
	if err != nil {
		return err
	}
	defer dec.Close()

	// start the new decryption and write out
	// any plain text produced
	pt, err = dec.Begin()
	if err != nil {
		return err
	}
	_, err = ofp.Write(pt)

	// read chunks of data and decrypt them,
	// writing the results to the output file
	for err == nil {
		var n int

		n, err = ifp.Read(ct)
		if err == nil {
			pt, err = dec.Update(ct[:n])
			if err == nil {
				_, err = ofp.Write(pt)
			}
		} else if err == io.EOF {
			err = nil
			break
		}
	}

	// finalize the decryption, writing any
	// remaining plain text to the output file
	if err == nil {
		pt, err = dec.End()
		if err == nil {
			_, err = ofp.Write(pt)
		}
	}

	return err
}
