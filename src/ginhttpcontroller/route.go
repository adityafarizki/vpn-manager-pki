package ginhttpcontroller

func (controller *GinHttpController) buildRoute() {
	controller.Router.GET("/", controller.mainPage)
	controller.Router.GET("/oidc-code-auth", controller.oidcCodeAuth)
	controller.Router.GET("/vpn-config", controller.downloadUserVpnConfig)
	controller.Router.LoadHTMLGlob("../templates/*")

	controller.Router.GET("/api/users", controller.getUsers)
	controller.Router.DELETE("/api/user/:email", controller.revokeUserAccess)
}
