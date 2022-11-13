package config

type Config struct {
	OidcClientId     string
	OidcClientSecret string
	OidcAuthUrl      string
	OidcTokenUrl     string
	OidcCertUrl      string
	OidcRedirectUrl  string
	StorageBucket    string
	VpnIpAddress     string
	AdminEmailList   []string
}
