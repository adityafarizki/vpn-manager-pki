package main

import (
	"fmt"

	"github.com/adityafarizki/vpn-gate-pki/config"
)

func main() {
	appConfig, err := config.ConfigFromEnv()
	if err != nil {
		fmt.Println("error occured during bootstrap: " + err.Error())
		return
	}

	ginController, err := Bootstrap(appConfig)
	if err != nil {
		fmt.Println("error occured during bootstrap: " + err.Error())
		return
	}

	ginController.Router.Run(appConfig.Address + ":" + appConfig.Port)
}
