package vpngatepki

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func BuildGinRouter() *gin.Engine {
	router := gin.Default()
	router.Use(errorHandler)
	router.GET("/", login)
	router.GET("/login", login)
	router.GET("/oidc-code-auth", ginOidcCodeAuth)
	router.GET("/vpn-config", ginGetUserVPNConfig)
	router.GET("/users", ginGetUsersList)
	router.DELETE("/user/:email", ginRevokeUserAccess)

	return router
}

func errorHandler(ctx *gin.Context) {
	ctx.Next()

	if len(ctx.Errors) > 0 {
		ctx.JSON(
			getErrorCode(ctx.Errors[0].Err), gin.H{"message": ctx.Errors[0].Err.Error()},
		)
	}
}

func login(ctx *gin.Context) {
	authUrl := getAuthUrl()
	ctx.PureJSON(http.StatusOK, gin.H{
		"authUrl": authUrl,
	})
}

func ginAuthenticateUser(ctx *gin.Context) (*User, error) {
	bearerAuth := ctx.Request.Header.Get("Authorization")
	token := strings.Split(bearerAuth, " ")

	if len(token) < 2 {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "bad bearer auth header"})
		return nil, errors.New("bad bearer auth header")
	}

	user, err := authenticateUserToken(token[1])
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "user token authentication failed, " + err.Error()})
		return nil, errors.New("user token authentication failed, " + err.Error())
	}

	return user, nil
}

func ginOidcCodeAuth(ctx *gin.Context) {
	query := ctx.Request.URL.Query()
	authCode := query["code"][0]

	token, err := getTokenFromAuthCode(authCode)

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

func ginGetUserVPNConfig(ctx *gin.Context) {
	user, err := ginAuthenticateUser(ctx)
	if err != nil {
		return
	}

	vpnConfig, err := GetUserVPNConfig(user)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.PureJSON(http.StatusOK, gin.H{"config": vpnConfig})
}

func ginGetUsersList(ctx *gin.Context) {
	user, err := ginAuthenticateUser(ctx)
	if err != nil {
		return
	}

	usersList, err := GetUsersList(user)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"users": usersList})
}

func ginRevokeUserAccess(ctx *gin.Context) {
	requester, err := ginAuthenticateUser(ctx)
	if err != nil {
		return
	}

	targetEmail := ctx.Param("email")
	err = RevokeUserAccess(requester, targetEmail)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{})
}
