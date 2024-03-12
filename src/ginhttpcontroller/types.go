package ginhttpcontroller

import (
	"strconv"

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

func NewGinHttpController(
	param *NewGinHttpControllerParam,
) *GinHttpController {
	controller := &GinHttpController{
		authInstance: param.AuthInstance,
		vpnManager:   param.VpnManager,
		userService:  param.UserService,
		Router:       gin.Default(),
	}
	controller.buildRoute()

	for i := 0; i < 100; i++ {
		param.UserService.RegisterUser("aaa" + strconv.Itoa(i) + "@" + "bbb" + ".com")
	}

	return controller
}
