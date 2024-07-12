package ginhttpcontroller

func (controller *GinHttpController) buildRoute(templateDir string) {
	controller.Router.GET("/", controller.mainPage)
	controller.Router.GET("/admin", controller.adminPage)
	controller.Router.GET("/oidc-code-auth", controller.oidcCodeAuth)
	controller.Router.GET("/vpn-config", controller.downloadUserVpnConfig)
	controller.Router.LoadHTMLGlob(templateDir + "/*")

	controller.Router.GET("/api/users", controller.getUsers)
	controller.Router.DELETE("/api/user/:email", controller.revokeUserAccess)
	controller.Router.PUT("/api/user/:email/reinstate", controller.reinstateUser)
}
