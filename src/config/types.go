package config

import (
	"github.com/adityafarizki/vpn-gate-pki/oidcauth"
)

type Config struct {
	OidcClientId     string
	OidcClientSecret string
	OidcAuthUrl      string
	OidcTokenUrl     string
	OidcCertUrl      string
	OidcRedirectUrl  string
	OidcProvider     oidcauth.OidcProvider
	StorageBucket    string
	VpnIpAddresses   []string
	DeploymentEnv    string
	AdminEmailList   []string
}
