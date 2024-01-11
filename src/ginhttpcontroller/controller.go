package ginhttpcontroller

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/gin-gonic/gin"
)

const AUTH_COOKIE_NAME = "authJwt"

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
	controller.Router.GET("/", controller.mainPage)
	controller.Router.GET("/login", controller.login)
	controller.Router.GET("/oidc-code-auth", controller.oidcCodeAuth)
	controller.Router.GET("/api/vpn-config", controller.getUserVpnConfig)
	controller.Router.GET("/api/users", controller.getUsers)
	controller.Router.DELETE("/api/user/:email", controller.revokeUserAccess)
	controller.Router.LoadHTMLGlob("templates/*")
}

func (controller *GinHttpController) mainPage(ctx *gin.Context) {
	jwtToken, err := ctx.Cookie(AUTH_COOKIE_NAME)
	if err != nil {
		ctx.Redirect(http.StatusTemporaryRedirect, controller.authInstance.GetAuthUrl())
		return
	}

	user, err := controller.authInstance.AuthenticateJwt(jwtToken)
	if err != nil {
		ctx.Redirect(http.StatusTemporaryRedirect, controller.authInstance.GetAuthUrl())
		return
	}

	ctx.HTML(200, "index.html", gin.H{"user": user})
}

func (controller *GinHttpController) oidcCodeAuth(ctx *gin.Context) {
	query := ctx.Request.URL.Query()
	authCode := query["code"][0]

	token, err := controller.authInstance.AuthenticateAuthCode(authCode)
	if err != nil {
		ctx.HTML(http.StatusUnauthorized, "error.html", gin.H{"error": err.Error()})
		return
	}

	user, err := controller.authInstance.AuthenticateJwt(token.Raw)
	if err != nil {
		ctx.HTML(http.StatusUnauthorized, "error.html", gin.H{"error": err.Error()})
		return
	}

	ctx.HTML(200, "index.html", gin.H{"user": user})
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
			return fmt.Errorf("unauthorized to do action %s", action)
		}
	}

	return nil
}

func (controller *GinHttpController) getUserVpnConfig(ctx *gin.Context) {
	authUser, err := controller.authenticateUser(ctx)
	if err != nil {
		return
	}

	// Verify if user's cert has been generated
	_, err = controller.userService.GetUserCert(authUser)
	if err != nil {
		if _, ok := err.(user.NotFoundError); ok {
			controller.userService.GenerateUserCert(authUser)
		} else {
			ctx.Error(err)
			return
		}
	}

	vpnConfig, err := controller.vpnManager.GetUserConfig(authUser)
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
		responseCode := http.StatusForbidden
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
		responseCode := http.StatusForbidden
		responseBody := gin.H{"message": "Unauthorized to do action RevokeUserAccess"}
		ctx.PureJSON(responseCode, responseBody)
		return
	}

	targetEmail := ctx.Param("email")
	err = controller.userService.RevokeUserCert(&user.User{Email: targetEmail})
	if err != nil {
		if serr, ok := err.(user.NotFoundError); ok {
			responseCode := http.StatusNotFound
			responseBody := gin.H{"message": "Revoking user access error: " + serr.Error()}
			ctx.PureJSON(responseCode, responseBody)
			return
		}
		responseCode := http.StatusServiceUnavailable
		responseBody := gin.H{"message": "Unexpected error has occured, please try again in a few moments"}
		ctx.PureJSON(responseCode, responseBody)
		return
	}

	ctx.JSON(http.StatusOK, &gin.H{})
}
