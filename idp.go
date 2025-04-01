package ubiq

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/youmark/pkcs8"
)

type OauthResponse struct {
	AccessToken string `json:"access_token"`
}

type SsoResponse struct {
	ApiCert      string `json:"api_cert"`
	PublicValue  string `json:"public_value"`
	SigningValue string `json:"signing_value"`
}

func (c Credentials) getOauthToken() (string, error) {
	client := &http.Client{}

	data := url.Values{}
	idpUser, _ := c.idpUsername()
	idpPass, _ := c.idpPassword()
	data.Set("client_id", c.config.Idp.TenantId)
	data.Set("client_secret", c.config.Idp.ClientSecret)
	data.Set("username", idpUser)
	data.Set("password", idpPass)
	data.Set("grant_type", "password")

	if c.config.Idp.Provider == "okta" {
		data.Set("scope", "openid offline_access okta.users.read okta.groups.read")
	} else if c.config.Idp.Provider == "entra" {
		data.Set("scope", fmt.Sprintf("api://%s/.default", c.config.Idp.TenantId))
	} else {
		return "", fmt.Errorf("unknown or no IDP provier specified: %s Check your configuration and try again", c.config.Idp.Provider)
	}

	resp, err := client.PostForm(
		c.config.Idp.TokenEndpointUrl,
		data,
	)

	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status (%v) Unable to fetch token from %s", resp.StatusCode, c.config.Idp.TokenEndpointUrl)
	}
	oauthResp := new(OauthResponse)
	err = json.NewDecoder(resp.Body).Decode(oauthResp)
	if err != nil {
		return "", err
	}

	return oauthResp.AccessToken, nil
}

func (c *Credentials) initIdp() error {
	// generate srsa
	srsa := generateRandomB64Str(33)

	c.params[credentialsSrsaId] = srsa

	// generate keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	// PEM format Private Key
	// privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

	// Encrypt and Save PK
	encryptedPrivateKeyBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(privateKey, []byte(srsa))
	encryptedPrivateKey := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedPrivateKeyBytes})
	if err != nil {
		return err
	}
	c.idpEncryptedPrivateKey = string(encryptedPrivateKey)

	// make csr
	subj := pkix.Name{
		CommonName:         generateRandomB64Str(18),
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Diego"},
		Organization:       []string{"Ubiq Security, Inc."},
		OrganizationalUnit: []string{"Ubiq Platform"},
	}
	csrTemplate := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return err
	}
	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	c.idpCsr = string(csrPem)
	// get idp token and cert
	err = c.getIdpTokenAndCert()
	if err != nil {
		return err
	}

	// initialized
	c.initialized = true

	return nil
}

func generateRandomB64Str(length int) string {
	randByteArr := make([]byte, length)
	rand.Read(randByteArr)
	generatedB64Str := base64.StdEncoding.EncodeToString(randByteArr)
	return generatedB64Str
}

func (c *Credentials) getIdpTokenAndCert() error {
	token, err := c.getOauthToken()
	if err != nil {
		return err
	}
	sso, err := c.getSso(token, c.idpCsr)
	if err != nil {
		return err
	}

	// Save Access Key
	c.params[credentialsPapiId] = sso.PublicValue
	// Save Secret Singing Value
	c.params[credentialsSapiId] = sso.SigningValue

	c.idpBase64Cert = base64.StdEncoding.EncodeToString([]byte(sso.ApiCert))
	certBlock, _ := pem.Decode([]byte(sso.ApiCert))
	idpCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	c.idpCertExpires = idpCert.NotAfter.Add(-1 * time.Minute)
	return nil
}

func (c *Credentials) renewIdpCert() {
	if isIdp, _ := c.isIdp(); isIdp {
		if c.idpCertExpires.Before(time.Now()) {
			c.getIdpTokenAndCert()
		}
	}
}

func (c Credentials) getSso(accessToken, csr string) (SsoResponse, error) {
	client := &http.Client{}
	host, _ := c.host()
	url := fmt.Sprintf("%s/%s/api/v3/scim/sso", host, c.config.Idp.CustomerId)
	bodyMap := map[string]string{
		"csr": csr,
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return SsoResponse{}, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return SsoResponse{}, err
	}
	req.Header = map[string][]string{
		"Authorization": {fmt.Sprintf("Bearer %s", accessToken)},
		"Accept":        {"application/json"},
		"Cache-control": {"no-cache"},
		"content-type":  {"application/json"},
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return SsoResponse{}, err
	}
	ssoResponse := new(SsoResponse)
	err = json.NewDecoder(resp.Body).Decode(ssoResponse)
	if err != nil {
		return SsoResponse{}, err
	}

	return *ssoResponse, nil
}

func (c Credentials) isIdp() (bool, error) {
	username, ok := c.idpUsername()

	if ok && len(username) > 0 && !c.initialized {
		return false, fmt.Errorf("credentials have not been initialized, but IDP Username has been provided")
	}

	return c.initialized, nil
}
