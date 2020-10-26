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
