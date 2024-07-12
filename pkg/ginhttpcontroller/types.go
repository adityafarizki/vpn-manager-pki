package ginhttpcontroller

import (
	"github.com/adityafarizki/vpn-gate-pki/pkg/oidcauth"
	"github.com/adityafarizki/vpn-gate-pki/pkg/user"
	"github.com/adityafarizki/vpn-gate-pki/pkg/vpnmanager"
	"github.com/gin-gonic/gin"
)

type GinHttpController struct {
	authInstance *oidcauth.OidcAuthService
	vpnManager   *vpnmanager.VpnManagerService
	userService  *user.UserService
	baseUrl      string
	Router       *gin.Engine
}

type NewGinHttpControllerParam struct {
	AuthInstance *oidcauth.OidcAuthService
	VpnManager   *vpnmanager.VpnManagerService
	UserService  *user.UserService
	BaseUrl      string
}

func NewGinHttpController(
	param *NewGinHttpControllerParam,
) *GinHttpController {
	controller := &GinHttpController{
		authInstance: param.AuthInstance,
		vpnManager:   param.VpnManager,
		userService:  param.UserService,
		Router:       gin.Default(),
		baseUrl:      param.BaseUrl,
	}
	controller.buildRoute()

	return controller
}
