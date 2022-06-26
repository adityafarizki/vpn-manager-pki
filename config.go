package main

import (
	"os"
	"strings"
)

type AppConfig struct {
	DeploymentEnv string
	ClientId      string
	ClientSecret  string
	AuthUrl       string
	TokenUrl      string
	CertUrl       string
	RedirectUrl   string
	S3BucketName  string
	VPNIPAdress   string
	AdminList     []string
}

func loadConfig() AppConfig {
	return AppConfig{
		DeploymentEnv: os.Getenv("DEPLOYMENT_ENV"),
		ClientId:      os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret:  os.Getenv("GOOGLE_CLIENT_SECRET"),
		AuthUrl:       os.Getenv("GOOGLE_AUTH_URL"),
		TokenUrl:      os.Getenv("GOOGLE_TOKEN_URL"),
		CertUrl:       os.Getenv("GOOGLE_CERT_URL"),
		RedirectUrl:   os.Getenv("APP_REDIRECT_URL"),
		S3BucketName:  os.Getenv("S3_BUCKET_NAME"),
		VPNIPAdress:   os.Getenv("VPN_IP_ADDRESS"),
		AdminList:     strings.Split(os.Getenv("ADMIN_LIST"), ","),
	}
}
