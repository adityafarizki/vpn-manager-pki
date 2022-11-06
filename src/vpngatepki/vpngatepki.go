package vpngatepki

import (
	"crypto/rsa"
	"errors"

	"github.com/adityafarizki/vpn-gate-pki/storage"
)

var Config *AppConfig
var AuthCerts map[string]*rsa.PublicKey
var CertMgr *CertManager
var VpnSettings *VPNSettings

func Bootstrap() error {
	var err error
	Config = loadConfig()
	AuthCerts, err = fetchAuthCerts(Config.CertUrl)
	if err != nil {
		return errors.New("Initializing auth cert error: " + err.Error())
	}

	cs, err := storage.NewCertAWSStorage("ca", "clients", Config.S3BucketName)
	if err != nil {
		return errors.New("Intializing storage error: " + err.Error())
	}

	CertMgr = &CertManager{CertStorage: cs}

	VpnSettings, err = initializeVPNSettings(CertMgr)
	if err != nil {
		return errors.New("Intializing vpn settings error: " + err.Error())
	}

	return nil
}

func InitPKI() error {
	return CertMgr.InitPKI()
}
