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

	scopes := []string{"api://23b3d855-cc27-4610-8290-653b02159435/email"}

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
