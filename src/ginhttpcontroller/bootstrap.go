package ginhttpcontroller

import (
	"fmt"

	"github.com/adityafarizki/vpn-gate-pki/certmanager"
	"github.com/adityafarizki/vpn-gate-pki/config"
	"github.com/adityafarizki/vpn-gate-pki/oidcauth"
	"github.com/adityafarizki/vpn-gate-pki/s3storage"
	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/adityafarizki/vpn-gate-pki/vpnmanager"
)

func Bootstrap(appConfig *config.Config) (*GinHttpController, error) {
	authInstance, err := oidcauth.NewGoogleOidcAuth(&oidcauth.GoogleOidcAuthConfig{
		AuthUrl:      appConfig.OidcAuthUrl,
		ClientId:     appConfig.OidcClientId,
		ClientSecret: appConfig.OidcClientSecret,
		TokenUrl:     appConfig.OidcTokenUrl,
		CertUrl:      appConfig.OidcCertUrl,
		RedirectUrl:  appConfig.OidcRedirectUrl,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	s3Storage, err := s3storage.NewS3Storage(appConfig.StorageBucket)
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	certManager := &certmanager.CertManager{
		CaDirPath:       "ca",
		UserCertDirPath: "clients",
		CertStorage:     s3Storage,
	}
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	vpnManager, err := vpnmanager.NewVpnManagerFromStorage(&vpnmanager.NewVpnManagerFromStorageParam{
		Storage:         s3Storage,
		ServerIPAddress: appConfig.VpnIpAddress,
		ConfigBasePath:  "ca",
		CertManager:     certManager,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	userService := &user.UserService{
		AdminList:   appConfig.AdminEmailList,
		CertManager: certManager,
	}

	ginController := NewGinHttpController(&NewGinHttpControllerParam{
		AuthInstance: authInstance,
		VpnManager:   vpnManager,
		UserService:  userService,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	return ginController, nil
}
