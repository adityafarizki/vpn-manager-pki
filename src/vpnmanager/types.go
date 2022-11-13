package vpnmanager

import (
	"github.com/adityafarizki/vpn-gate-pki/certmanager"
)

type VpnManagerService struct {
	ServerIPAddress string
	TlsCrypt        string
	Template        string
	certManager     *certmanager.CertManager
}

type NewVpnManagerFromStorageParam struct {
	Storage         certmanager.IStorage
	ServerIPAddress string
	ConfigBasePath  string
	CertManager     *certmanager.CertManager
}
