package main

import (
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

	router.Run()
}

func login(ctx *gin.Context) {
	authUrl := getAuthUrl()
	fmt.Println(authUrl)
	ctx.PureJSON(http.StatusOK, gin.H{
		"authUrl": authUrl,
	})
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
	bearerAuth := ctx.Request.Header.Get("Authorization")
	token := strings.Split(bearerAuth, " ")
	if len(token) < 2 {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "bad bearer auth header"})
		return
	}

	user, err := authenticateUserToken(token[1])
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "user token authentication failed, " + err.Error()})
		return
	}
	vpnConfig, err := getUserVPNConfig(user)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "generating user vpn config failed, " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"config": vpnConfig})
}
