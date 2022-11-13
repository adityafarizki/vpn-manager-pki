package httpcontroller

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/gin-gonic/gin"
)

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

	return controller
}

func (controller *GinHttpController) buildRoute() {
	controller.Router.GET("/", controller.login)
	controller.Router.GET("/login", controller.login)
	controller.Router.GET("/oidc-code-auth", controller.oidcCodeAuth)
	controller.Router.GET("/vpn-config", controller.getUserVpnConfig)
	controller.Router.GET("/users", controller.getUsers)
	controller.Router.DELETE("/user/:email", controller.revokeUserAccess)
}

func (controller *GinHttpController) login(ctx *gin.Context) {
	authUrl := controller.authInstance.GetAuthUrl()
	ctx.PureJSON(http.StatusOK, gin.H{
		"authUrl": authUrl,
	})
}

func (controller *GinHttpController) authenticateUser(ctx *gin.Context) (*user.User, error) {
	bearerAuth := ctx.Request.Header.Get("Authorization")
	token := strings.Split(bearerAuth, " ")

	if len(token) < 2 {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "bad bearer auth header"})
		return nil, errors.New("bad bearer auth header")
	}

	jwtToken := token[1]
	user, err := controller.authInstance.AuthenticateJwt(jwtToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "user token authentication failed, " + err.Error()})
		return nil, errors.New("user token authentication failed, " + err.Error())
	}

	return user, nil
}

func (controller *GinHttpController) authorizeAction(user *user.User, action string) error {
	if action == "GetUsersList" || action == "RevokeUserAccess" {
		if controller.userService.IsUserAdmin(user) {
			return nil
		} else {
			return fmt.Errorf("Unauthorized to do action %s", action)
		}
	}

	return nil
}

func (controller *GinHttpController) oidcCodeAuth(ctx *gin.Context) {
	query := ctx.Request.URL.Query()
	authCode := query["code"][0]

	token, err := controller.authInstance.AuthenticateAuthCode(authCode)

	var responseCode int
	var responseBody gin.H
	if err != nil {
		responseCode = http.StatusUnauthorized
		responseBody = gin.H{"message": "parsing token error, " + err.Error()}
	} else {
		responseCode = http.StatusOK
		responseBody = gin.H{"token": token.Raw}
	}

	ctx.JSON(responseCode, responseBody)
}

func (controller *GinHttpController) getUserVpnConfig(ctx *gin.Context) {
	user, err := controller.authenticateUser(ctx)
	if err != nil {
		return
	}

	vpnConfig, err := controller.vpnManager.GetUserConfig(user)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.PureJSON(http.StatusOK, gin.H{"config": vpnConfig})
}

func (controller *GinHttpController) getUsers(ctx *gin.Context) {
	user, err := controller.authenticateUser(ctx)
	if err != nil {
		return
	}

	err = controller.authorizeAction(user, "GetUsersList")
	if err != nil {
		responseCode := http.StatusUnauthorized
		responseBody := gin.H{"message": "Unauthorized to do action GetUsersList"}
		ctx.PureJSON(responseCode, responseBody)
		return
	}

	usersList, err := controller.userService.GetUsersList()
	if err != nil {
		responseCode := http.StatusServiceUnavailable
		responseBody := gin.H{"message": "Unexpected error has occured, please try again in a few moments"}
		ctx.PureJSON(responseCode, responseBody)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"users": usersList})
}

func (controller *GinHttpController) revokeUserAccess(ctx *gin.Context) {
	callingUser, err := controller.authenticateUser(ctx)
	if err != nil {
		return
	}

	err = controller.authorizeAction(callingUser, "RevokeUserAccess")
	if err != nil {
		responseCode := http.StatusUnauthorized
		responseBody := gin.H{"message": "Unauthorized to do action RevokeUserAccess"}
		ctx.PureJSON(responseCode, responseBody)
		return
	}

	targetEmail := ctx.Param("email")
	err = controller.userService.RevokeUserCert(&user.User{Email: targetEmail})
	if err != nil {
		responseCode := http.StatusServiceUnavailable
		responseBody := gin.H{"message": "Unexpected error has occured, please try again in a few moments"}
		ctx.PureJSON(responseCode, responseBody)
		return
	}

	ctx.JSON(http.StatusOK, &gin.H{})
}
