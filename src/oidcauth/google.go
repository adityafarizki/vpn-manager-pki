package oidcauth

import (
	"fmt"
)

type GoogleOidcAuthConfig struct {
	ClientId     string
	ClientSecret string
	AuthUrl      string
	TokenUrl     string
	CertUrl      string
	RedirectUrl  string
}

func NewGoogleOidcAuth(config *GoogleOidcAuthConfig) (*OidcAuthService, error) {
	authKeys, err := getCertsAuthKeys(config.CertUrl)
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
