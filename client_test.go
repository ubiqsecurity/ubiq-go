package ubiq

import (
	"net/http"
	"testing"
)

func TestGetRequest(t *testing.T) {
	var client httpClient

	rsp, err := client.Get("https://dashboard.ubiqsecurity.com/")
	if rsp != nil {
		defer rsp.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	if rsp.StatusCode != http.StatusOK {
		t.Fatalf(rsp.Status)
	}
}
