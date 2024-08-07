package ginhttpcontroller

import (
	"errors"
	"fmt"
	"strings"

	"github.com/adityafarizki/vpn-gate-pki/pkg/user"
	"github.com/gin-gonic/gin"
)

func (controller *GinHttpController) getBearerToken(ctx *gin.Context) (string, error) {
	bearerAuth := ctx.Request.Header.Get("Authorization")
	token := strings.Split(bearerAuth, " ")

	if len(token) < 2 {
		return "", errors.New("bad bearer auth header")
	}

	return token[1], nil
}

func (controller *GinHttpController) authorizeAction(user *user.User, action string) error {
	if action == "GetUsersList" || action == "RevokeUserAccess" || action == "OpenAdminPage" || action == "ReinstateUserAccess" {
		if controller.userService.IsUserAdmin(user) {
			return nil
		} else {
			return fmt.Errorf("unauthorized to do action %s", action)
		}
	}

	return nil
}
