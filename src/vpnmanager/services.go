package vpnmanager

import (
	"fmt"

	"github.com/adityafarizki/vpn-gate-pki/user"
)

func NewVpnManagerFromStorage(param *NewVpnManagerFromStorageParam) (*VpnManagerService, error) {
	tlsCrypt, err := param.Storage.GetFile(param.ConfigBasePath + "/tls-crypt.pem")
	if err != nil {
		return nil, fmt.Errorf("error creating vpn manager: %w", err)
	}

	template, err := param.Storage.GetFile(param.ConfigBasePath + "/template.ovpn")
	if err != nil {
		return nil, fmt.Errorf("error creating vpn manager: %w", err)
	}

	return &VpnManagerService{
		ServerIPAddress: param.ServerIPAddress,
		TlsCrypt:        string(tlsCrypt),
		Template:        string(template),
		certManager:     param.CertManager,
	}, nil
}

func (vpn *VpnManagerService) GetUserConfig(user *user.User) (string, error) {
	cert, privkey, err := vpn.certManager.GetCert(user.Email)
	if err != nil {
		return "", fmt.Errorf("getting user config error: %w", err)
	}

	ca, _, err := vpn.certManager.GetRootCert()
	if err != nil {
		return "", fmt.Errorf("getting user config error: %w", err)
	}

	pemCert, err := vpn.certManager.CertToPem(cert)
	if err != nil {
		return "", fmt.Errorf("getting user config error: %w", err)
	}

	pemKey, err := vpn.certManager.KeyToPem(privkey)
	if err != nil {
		return "", fmt.Errorf("getting user config error: %w", err)
	}

	pemCA, err := vpn.certManager.CertToPem(ca)
	if err != nil {
		return "", fmt.Errorf("getting user config error: %w", err)
	}

	remoteLine := fmt.Sprintf("remote %s 1194", vpn.ServerIPAddress)
	config := fmt.Sprintf(
		"%s\n%s\n<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n<tls-crypt>\n%s\n</tls-crypt>",
		remoteLine,
		vpn.Template,
		pemCA,
		pemCert,
		pemKey,
		vpn.TlsCrypt,
	)
	return config, nil
}
