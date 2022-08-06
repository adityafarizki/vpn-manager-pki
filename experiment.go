package vpngatepki

import (
	"fmt"
	"io/fs"
	"io/ioutil"

	"github.com/adityafarizki/vpn-gate-pki/storage"
)

func testCertManager() {
	// if err := InitPKI("certs"); err != nil {
	// 	fmt.Printf("Init PKI error: %s\n", err)
	// }

	cs, err := storage.NewCertAWSStorage(
		"ca", "clients", "vpn-bucket-881287946390-ap-southeast-1",
	)
	if err != nil {
		fmt.Printf("Initializing AWS storage error: %s\n", err)
		return
	}

	cm = &CertManager{
		certStorage: cs,
	}

	vpnTemplate, err := cm.GetVpnTemplate()
	if err != nil {
		fmt.Printf("Getting VPN Template Error: %s\n", err)
		return
	}

	tlsCrypt, err := cm.GetTlsCrypt()
	if err != nil {
		fmt.Printf("Getting TLS Crypt Error: %s\n", err)
		return
	}

	vpnSettings = &VPNSettings{
		ServerIPAddress: "34.142.227.244",
		Template:        vpnTemplate,
		TlsCrypt:        tlsCrypt,
	}

	_, err = cm.CreateNewClientCert("adot")
	if err != nil {
		fmt.Printf("Generating client cert error: %s\n", err)
	}

	config, err := GenerateVPNConfig("adot", cm, vpnSettings)
	if err != nil {
		fmt.Printf("Generating VPN config error: %s\n", err)
	}

	err = ioutil.WriteFile("config.ovpn", []byte(config), fs.FileMode(0755))
	if err != nil {
		fmt.Printf("Writing VPN config error: %s\n", err)
	}
}
