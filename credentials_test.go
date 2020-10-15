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

func verifyCredentials(t *testing.T, err error, c Credentials) {
	if err != nil {
		t.Fatal(err)
	}
	if !c.valid() {
		t.FailNow()
	}
}

func TestAnyCredentials(t *testing.T) {
	c, err := NewCredentials()
	verifyCredentials(t, err, c)
}

func TestExplicitCredentials(t *testing.T) {
	// default host
	c, err := NewCredentials("", "", "")
	verifyCredentials(t, err, c)

	// explicit host
	c, err = NewCredentials("", "", "", "")
	verifyCredentials(t, err, c)
}
