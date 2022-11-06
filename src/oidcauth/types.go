package oidcauth

import "crypto/rsa"

type OidcAuthService struct {
	ClientId     string
	ClientSecret string
	AuthUrl      string
	TokenUrl     string
	AuthKeys     map[string]*rsa.PublicKey
	RedirectUrl  string
	Scopes       []string
}
