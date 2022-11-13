package httpcontroller

import (
	"github.com/adityafarizki/vpn-gate-pki/oidcauth"
	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/adityafarizki/vpn-gate-pki/vpnmanager"
	"github.com/gin-gonic/gin"
)

type GinHttpController struct {
	authInstance *oidcauth.OidcAuthService
	vpnManager   *vpnmanager.VpnManagerService
	userService  *user.UserService
	Router       *gin.Engine
}

type NewGinHttpControllerParam struct {
	AuthInstance *oidcauth.OidcAuthService
	VpnManager   *vpnmanager.VpnManagerService
	UserService  *user.UserService
}
