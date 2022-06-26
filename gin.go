package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func runGinServer() {
	router := gin.Default()
	router.GET("/", login)
	router.GET("/login", login)
	router.GET("/oidc-code-auth", ginOidcCodeAuth)
	router.GET("/vpn-config", ginGetUserVPNConfig)
	router.GET("/users-list", ginGetUsersList)
	router.DELETE("/revoke/:email", ginRevokeUserAccess)

	router.Run()
}

func login(ctx *gin.Context) {
	authUrl := getAuthUrl()
	fmt.Println(authUrl)
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

	vpnConfig, err := getUserVPNConfig(user)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "generating user vpn config failed, " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"config": vpnConfig})
}

func ginGetUsersList(ctx *gin.Context) {
	user, err := ginAuthenticateUser(ctx)
	if err != nil {
		return
	}

	usersList, err := getUsersList(user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "getting users list failed, " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"users": usersList})
}

func ginRevokeUserAccess(ctx *gin.Context) {
	fmt.Println("found here")
	requester, err := ginAuthenticateUser(ctx)
	if err != nil {
		return
	}

	target := ctx.Param("email")
	err = revokeUserAccess(requester, target)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "revoking user access failed, " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{})
}
