package vpnmanager

import (
	"fmt"
	"strings"

	"github.com/adityafarizki/vpn-gate-pki/user"
)

func NewVpnManagerFromStorage(param *NewVpnManagerFromStorageParam) (*VpnManagerService, error) {
	tlsCryptPath := param.ConfigBasePath + "/tls_crypt.pem"
	tlsCrypt, err := param.Storage.GetFile(tlsCryptPath)
	if err != nil {
		return nil, fmt.Errorf("error creating vpn manager: %w "+tlsCryptPath, err)
	}

	templatePath := param.ConfigBasePath + "/template.ovpn"
	template, err := param.Storage.GetFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("error creating vpn manager: %w "+templatePath, err)
	}

	return &VpnManagerService{
		ServerIPAddresses: param.ServerIPAddresses,
		TlsCrypt:          string(tlsCrypt),
		Template:          string(template),
		certManager:       param.CertManager,
	}, nil
}

func (vpn *VpnManagerService) GetUserConfig(user *user.User) (map[string]string, error) {
	cert, privkey, err := vpn.certManager.GetCert(user.Email)
	if err != nil {
		return nil, fmt.Errorf("getting user config error: %w", err)
	}

	ca, _, err := vpn.certManager.GetRootCert()
	if err != nil {
		return nil, fmt.Errorf("getting user config error: %w", err)
	}

	pemCert, err := vpn.certManager.CertToPem(cert)
	if err != nil {
		return nil, fmt.Errorf("getting user config error: %w", err)
	}

	pemKey, err := vpn.certManager.KeyToPem(privkey)
	if err != nil {
		return nil, fmt.Errorf("getting user config error: %w", err)
	}

	pemCA, err := vpn.certManager.CertToPem(ca)
	if err != nil {
		return nil, fmt.Errorf("getting user config error: %w", err)
	}

	config := map[string]string{}
	for _, ipAddress := range vpn.ServerIPAddresses {
		remote := strings.Split(ipAddress, "=")
		remoteName := remote[0]
		remoteIp := remote[1]

		remoteLine := fmt.Sprintf("remote %s 1194", remoteIp)
		config[remoteName] = fmt.Sprintf(
			"%s\n%s\n<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n<tls-crypt>\n%s\n</tls-crypt>",
			remoteLine,
			vpn.Template,
			pemCA,
			pemCert,
			pemKey,
			vpn.TlsCrypt,
		)
	}
	return config, nil
}
