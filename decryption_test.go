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

package ubiq

import (
	"bytes"
	"testing"
)

func TestNoDecryption(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	decryption, err := NewDecryption(credentials)
	if decryption != nil {
		defer decryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSimpleDecryption(t *testing.T) {
	var pt []byte = []byte("abc")

	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := Encrypt(credentials, pt)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := Decrypt(credentials, ct)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, recovered) {
		t.FailNow()
	}
}

func TestSingleDecryption(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	encryption, err := NewEncryption(credentials, 1)
	if encryption != nil {
		defer encryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	ct, err := encryption.Begin()
	if err != nil {
		t.Fatal(err)
	}

	tmp, _ := encryption.Update([]byte("abc"))
	ct = append(ct, tmp...)

	tmp, err = encryption.End()
	if err != nil {
		t.Fatal(err)
	}

	ct = append(ct, tmp...)

	decryption, err := NewDecryption(credentials)
	if decryption != nil {
		defer decryption.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	pt, err := decryption.Begin()
	if err != nil {
		t.Fatal(err)
	}

	tmp, err = decryption.Update(ct)
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	tmp, err = decryption.End()
	if err != nil {
		t.Fatal(err)
	}
	pt = append(pt, tmp...)

	if !bytes.Equal(pt, []byte("abc")) {
		t.FailNow()
	}
}
