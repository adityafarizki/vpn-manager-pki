package vpngatepki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"testing"

	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/adityafarizki/vpn-gate-pki/certmanager"
	"github.com/adityafarizki/vpn-gate-pki/config"
	controller "github.com/adityafarizki/vpn-gate-pki/ginhttpcontroller"
	"github.com/adityafarizki/vpn-gate-pki/oidcauth"
	"github.com/adityafarizki/vpn-gate-pki/s3storage"
	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/adityafarizki/vpn-gate-pki/vpnmanager"
)

type KeyConfig struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyId      string
}

type TestFixture struct {
	AuthInstance *oidcauth.OidcAuthService
	Storage      *s3storage.S3Storage
	CertManager  *certmanager.CertManager
	VpnManager   *vpnmanager.VpnManagerService
	UserService  *user.UserService
	Controller   *controller.GinHttpController
	KeyConfig    *KeyConfig
}

func TestVpnGatePki(t *testing.T) {
	gin.DefaultWriter = io.Discard
	RegisterFailHandler(Fail)
	RunSpecs(t, "VpnGatePki Suite")
}

func generateJwtKeys() (*KeyConfig, error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	publickey := &privatekey.PublicKey
	jwtKeyId := randomString(30)

	return &KeyConfig{
		PrivateKey: privatekey,
		PublicKey:  publickey,
		KeyId:      jwtKeyId,
	}, nil
}

func Bootstrap(appConfig *config.Config) (*TestFixture, error) {
	keyConfig, err := generateJwtKeys()
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	authKeys := map[string]*rsa.PublicKey{
		keyConfig.KeyId: keyConfig.PublicKey,
	}
	authInstance := &oidcauth.OidcAuthService{
		AuthUrl:      appConfig.OidcAuthUrl,
		ClientId:     appConfig.OidcClientId,
		ClientSecret: appConfig.OidcClientSecret,
		TokenUrl:     appConfig.OidcTokenUrl,
		AuthKeys:     authKeys,
		RedirectUrl:  appConfig.OidcRedirectUrl,
	}
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

	ginController := controller.NewGinHttpController(&controller.NewGinHttpControllerParam{
		AuthInstance: authInstance,
		VpnManager:   vpnManager,
		UserService:  userService,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	return &TestFixture{
		AuthInstance: authInstance,
		Storage:      s3Storage,
		CertManager:  certManager,
		VpnManager:   vpnManager,
		UserService:  userService,
		Controller:   ginController,
		KeyConfig:    keyConfig,
	}, nil
}
