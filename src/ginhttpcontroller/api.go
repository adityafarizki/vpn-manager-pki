package ginhttpcontroller

import (
	"net/http"

	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/gin-gonic/gin"
)

func (controller *GinHttpController) login(ctx *gin.Context) {
	authUrl := controller.authInstance.GetAuthUrl()
	ctx.PureJSON(http.StatusOK, gin.H{
		"authUrl": authUrl,
	})
}

func (controller *GinHttpController) getUsers(ctx *gin.Context) {
	token, err := controller.getBearerToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "bad bearer auth header, " + err.Error()})
		ctx.Status(403)
		return
	}

	user, err := controller.authInstance.AuthenticateJwt(token)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "authenticating user failed, " + err.Error()})
		ctx.Status(403)
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
	token, err := controller.getBearerToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "bad bearer auth header, " + err.Error()})
		ctx.Status(403)
		return
	}

	callingUser, err := controller.authInstance.AuthenticateJwt(token)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "authenticating user failed, " + err.Error()})
		ctx.Status(403)
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
