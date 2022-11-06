package httpcontroller

import (
	"github.com/adityafarizki/vpn-gate-pki/oidcauth"
	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/adityafarizki/vpn-gate-pki/vpnmanager"
	"github.com/gin-gonic/gin"
)

type GinHttpController struct {
	authInstance oidcauth.OidcAuthService
	vpnManager   vpnmanager.VpnManagerService
	userService  user.UserService
	router       *gin.Engine
}
