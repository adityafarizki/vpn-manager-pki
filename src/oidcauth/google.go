package oidcauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
)

func NewGoogleOidcAuth(config *GoogleOidcAuthConfig) (*OidcAuthService, error) {
	authKeys, err := getGoogleAuthKeys(config.CertUrl)
	if err != nil {
		return nil, fmt.Errorf("error initializing Google auth: %w", err)
	}

	scopes := []string{"https://www.googleapis.com/auth/userinfo.email"}

	return &OidcAuthService{
		ClientId:     config.ClientId,
		ClientSecret: config.ClientSecret,
		AuthUrl:      config.AuthUrl,
		TokenUrl:     config.TokenUrl,
		AuthKeys:     authKeys,
		RedirectUrl:  config.RedirectUrl,
		Scopes:       scopes,
	}, nil
}

func getGoogleAuthKeys(certUrl string) (map[string]*rsa.PublicKey, error) {
	client := http.DefaultClient
	req, err := http.NewRequest("GET", certUrl, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	certs := map[string]string{}
	json.Unmarshal(respBody, &certs)

	result := map[string]*rsa.PublicKey{}
	for key, element := range certs {
		certBlock, _ := pem.Decode([]byte(element))
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}
		pubKey := cert.PublicKey.(*rsa.PublicKey)

		result[key] = pubKey
	}

	return result, nil
}
