package vpnmanager

import "github.com/adityafarizki/vpn-gate-pki/user"

type VpnManagerService struct {
	ServerIPAddress string
	TlsCrypt        string
	Template        string
	userService     *user.UserService
}
