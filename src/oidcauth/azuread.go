package oidcauth

import "fmt"

type NewAzureAdOidcAuthConfig struct {
	ClientId     string
	ClientSecret string
	AuthUrl      string
	TokenUrl     string
	JwkUrl       string
	RedirectUrl  string
}

func NewAzureAdOidcAuth(config *NewAzureAdOidcAuthConfig) (*OidcAuthService, error) {
	authKeys, err := getJwkSetAuthKeys(config.JwkUrl)
	if err != nil {
		return nil, fmt.Errorf("error initializing Google auth: %w", err)
	}

	scopes := []string{"email"}

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
