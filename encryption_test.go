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
	"testing"
)

func TestNoEncryption(t *testing.T) {
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
}

func TestSimpleEncryption(t *testing.T) {
	credentials, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Encrypt(credentials, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSingleEncryption(t *testing.T) {
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
}

func TestTooManyEncryption(t *testing.T) {
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

	_, err = encryption.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = encryption.End()
	if err != nil {
		t.Fatal(err)
	}

	_, err = encryption.Begin()
	if err == nil {
		t.Fatal(err)
	}
}
