package main

import (
	"fmt"

	"github.com/adityafarizki/vpn-gate-pki/certmanager"
	"github.com/adityafarizki/vpn-gate-pki/config"
	gin "github.com/adityafarizki/vpn-gate-pki/ginhttpcontroller"
	"github.com/adityafarizki/vpn-gate-pki/oidcauth"
	"github.com/adityafarizki/vpn-gate-pki/s3storage"
	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/adityafarizki/vpn-gate-pki/vpnmanager"
)

func Bootstrap(appConfig *config.Config) (*gin.GinHttpController, error) {
	authInstance, err := setupAuthInstance(appConfig)
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	s3Storage, err := s3storage.NewS3Storage(appConfig.StorageBucket)
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	certManager := &certmanager.CertManager{
		CaDirPath:       appConfig.CaBaseDir,
		UserCertDirPath: appConfig.ClientCertBaseDir,
		CertStorage:     s3Storage,
	}

	vpnManager, err := vpnmanager.NewVpnManagerFromStorage(&vpnmanager.NewVpnManagerFromStorageParam{
		Storage:           s3Storage,
		ServerIPAddresses: appConfig.VpnIpAddresses,
		ConfigBasePath:    appConfig.ConfigBaseDir,
		CertManager:       certManager,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	userService := &user.UserService{
		AdminList:       appConfig.AdminEmailList,
		CertManager:     certManager,
		DataStorage:     s3Storage,
		UserDataDirPath: appConfig.UserDataDirPath,
	}

	ginController := gin.NewGinHttpController(&gin.NewGinHttpControllerParam{
		AuthInstance: authInstance,
		VpnManager:   vpnManager,
		UserService:  userService,
		BaseUrl:      appConfig.BaseUrl,
	})

	return ginController, nil
}

func setupAuthInstance(appConfig *config.Config) (*oidcauth.OidcAuthService, error) {
	switch appConfig.OidcProvider {
	case oidcauth.Google:
		return oidcauth.NewGoogleOidcAuth(&oidcauth.GoogleOidcAuthConfig{
			AuthUrl:      appConfig.OidcAuthUrl,
			ClientId:     appConfig.OidcClientId,
			ClientSecret: appConfig.OidcClientSecret,
			TokenUrl:     appConfig.OidcTokenUrl,
			CertUrl:      appConfig.OidcCertUrl,
			RedirectUrl:  appConfig.OidcRedirectUrl,
		})
	case oidcauth.AzureAD:
		return oidcauth.NewAzureAdOidcAuth(&oidcauth.NewAzureAdOidcAuthConfig{
			AuthUrl:      appConfig.OidcAuthUrl,
			ClientId:     appConfig.OidcClientId,
			ClientSecret: appConfig.OidcClientSecret,
			TokenUrl:     appConfig.OidcTokenUrl,
			JwkUrl:       appConfig.OidcCertUrl,
			RedirectUrl:  appConfig.OidcRedirectUrl,
		})
	default:
		return nil, fmt.Errorf("OIDC type config not found")
	}
}
