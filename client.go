package ubiq

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// The Ubiq Go library version.
	Version = "2.2.3"
)

// httpClient is a relatively thin wrapper around Go's http.Client
// that adds Ubiq authentication to requests that pass through it
type httpClient struct {
	client     http.Client
	papi, sapi string
}

func newHttpClient(c Credentials) httpClient {
	papi, _ := c.papi()
	sapi, _ := c.sapi()

	return httpClient{papi: papi, sapi: sapi}
}

func (h *httpClient) Get(url string) (*http.Response, error) {
	var req *http.Request
	var rsp *http.Response
	var err error

	req, err = http.NewRequest("GET", url, nil)
	if err == nil {
		rsp, err = h.Do(req)
	}
	return rsp, err
}

func (h *httpClient) Post(url, contentType string, body io.Reader) (
	*http.Response, error) {
	return h.upload("POST", url, contentType, body)
}

func (h *httpClient) Patch(url, contentType string, body io.Reader) (
	*http.Response, error) {
	return h.upload("PATCH", url, contentType, body)
}

func (h *httpClient) upload(method, url, contentType string, body io.Reader) (
	*http.Response, error) {
	var req *http.Request
	var rsp *http.Response
	var err error

	req, err = http.NewRequest(method, url, body)
	if err == nil {
		req.Header.Set("Content-Type", contentType)
		rsp, err = h.Do(req)
	}
	return rsp, err
}

// Do wraps Go's http.Client.Do function but implements the signature
// scheme v0 described here: https://gitlab.com/ubiqsecurity/ubiq-api
func (h *httpClient) Do(req *http.Request) (*http.Response, error) {
	now := time.Now()

	req.Host = req.URL.Host
	req.Header.Set("Host", req.Host)

	// the headers wrapped in parentheses aren't real headers,
	// but adding them to the request simplifies the code later
	// that calculates the signature over the included headers.
	// the parentheses-wrapped headers are later removed before
	// the request is sent.

	reqtgt := strings.ToLower(req.Method)
	reqtgt += " " + req.URL.EscapedPath()
	if len(req.URL.RawQuery) > 0 {
		reqtgt += "?" + req.URL.RawQuery
	}
	req.Header.Set("(request-target)", reqtgt)

	req.Header.Set("(created)", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("Date", now.UTC().Format(http.TimeFormat))

	req.Header.Set("User-Agent", "ubiq-go/"+Version)

	dig := sha512.New()
	if req.Body != nil {
		tee := io.TeeReader(req.Body, dig)
		body, _ := io.ReadAll(tee)
		req.Body.Close()

		if len(req.Header.Get("Content-Type")) == 0 {
			req.Header.Set(
				"Content-Type",
				http.DetectContentType(body))
		}

		req.ContentLength = int64(len(body))
		req.Header.Set(
			"Content-Length",
			strconv.FormatInt(req.ContentLength, 10))

		req.Body = io.NopCloser(bytes.NewBuffer(body))
	}
	sum := dig.Sum(nil)
	req.Header.Set(
		"Digest",
		"SHA-512="+base64.StdEncoding.EncodeToString(sum))

	headers := []string{}
	dig = hmac.New(sha512.New, []byte(h.sapi))
	for _, h := range []string{
		"(created)",
		"(request-target)",
		"Content-Length",
		"Content-Type",
		"Date",
		"Digest",
		"Host"} {
		if v := req.Header.Get(h); v != "" {
			lh := strings.ToLower(h)

			headers = append(headers, lh)

			s := lh + ": " + v + "\n"
			dig.Write([]byte(s))
		}
	}
	sum = dig.Sum(nil)

	req.Header.Set(
		"Signature",
		"keyId=\""+h.papi+"\""+
			", algorithm=\"hmac-sha512\""+
			", created="+req.Header.Get("(created)")+
			", headers=\""+
			strings.Join(headers, " ")+"\""+
			", signature=\""+
			base64.StdEncoding.EncodeToString(sum)+"\"")

	// remove "fake" headers

	req.Header.Del("(request-target)")
	req.Header.Del("(created)")

	return h.client.Do(req)
}
