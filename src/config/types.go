package config

import (
	"github.com/adityafarizki/vpn-gate-pki/oidcauth"
)

type Config struct {
	OidcClientId      string
	OidcClientSecret  string
	OidcAuthUrl       string
	OidcTokenUrl      string
	OidcCertUrl       string
	OidcRedirectUrl   string
	OidcProvider      oidcauth.OidcProvider
	StorageBucket     string
	VpnIpAddresses    []string
	AdminEmailList    []string
	BaseUrl           string
	Port              string `optional:"yes" default:"8080"`
	Address           string `optional:"yes" default:"0.0.0.0"`
	CaBaseDir         string `optional:"yes" default:"ca"`
	ClientCertBaseDir string `optional:"yes" default:"clients"`
	UserDataDirPath   string `optional:"yes" default:"users"`
	ConfigBaseDir     string `optional:"yes" default:"ca"`
}
