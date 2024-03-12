package ginhttpcontroller

import (
	"archive/zip"
	"bytes"
	"fmt"
	"log"
	"net/http"

	cmerr "github.com/adityafarizki/vpn-gate-pki/commonerrors"
	"github.com/gin-gonic/gin"
)

const AUTH_COOKIE_NAME = "authJwt"
const AUTH_COOKIE_TIME = 600

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

func (controller *GinHttpController) adminPage(ctx *gin.Context) {
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

	err = controller.authorizeAction(user, "OpenAdminPage")
	if err != nil {
		responseCode := http.StatusForbidden
		responseBody := gin.H{"message": "Unauthorized to do action OpenAdminPage"}
		ctx.PureJSON(responseCode, responseBody)
		return
	}

	ctx.HTML(200, "admin.html", nil)
}

func (controller *GinHttpController) oidcCodeAuth(ctx *gin.Context) {
	query := ctx.Request.URL.Query()
	authCode := query["code"][0]

	token, err := controller.authInstance.AuthenticateAuthCode(authCode)
	if err != nil {
		ctx.HTML(http.StatusUnauthorized, "error.html", gin.H{"error": err.Error()})
		return
	}

	ctx.SetCookie(AUTH_COOKIE_NAME, token.Raw, AUTH_COOKIE_TIME, "/", ctx.Request.Header.Get("Host"), true, false)
	ctx.Redirect(http.StatusTemporaryRedirect, "/")
}

func (controller *GinHttpController) downloadUserVpnConfig(ctx *gin.Context) {
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

	// Verify if user's cert has been generated
	_, err = controller.userService.GetUserCert(user)
	if err != nil {
		if _, ok := err.(cmerr.NotFoundError); ok {
			controller.userService.RegisterUser(user.Email)
		} else {
			responseCode := http.StatusInternalServerError
			errMessage := fmt.Errorf("Error getting user cert %s", err)
			ctx.String(responseCode, errMessage.Error())
			return
		}
	}

	vpnConfig, err := controller.vpnManager.GetUserConfig(user)
	if err != nil {
		ctx.Error(err)
		return
	}

	zippedConfig, err := zipConfig(vpnConfig)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.Header("Content-Description", "File Transfer")
	ctx.Header("Content-Transfer-Encoding", "binary")
	ctx.Header("Content-Disposition", "attachment; filename="+"openVPN.zip")
	ctx.Data(http.StatusOK, "application/octet-stream", zippedConfig)
}

func zipConfig(config map[string]string) ([]byte, error) {
	buff := new(bytes.Buffer)
	writer := zip.NewWriter(buff)

	for filename, content := range config {
		f, err := writer.Create(filename + ".ovpn")
		if err != nil {
			log.Fatal(err)
			return nil, fmt.Errorf("zipping vpn configs error: %s", err)
		}
		_, err = f.Write([]byte(content))
		if err != nil {
			log.Fatal(err)
			return nil, fmt.Errorf("zipping vpn configs error: %s", err)
		}
	}
	err := writer.Close()
	if err != nil {
		log.Fatal(err)
		return nil, fmt.Errorf("zipping vpn configs error: %s", err)
	}

	return buff.Bytes(), nil
}
