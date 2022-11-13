package main

import (
	"context"
	"fmt"

	"github.com/adityafarizki/vpn-gate-pki/certmanager"
	"github.com/adityafarizki/vpn-gate-pki/config"
	controller "github.com/adityafarizki/vpn-gate-pki/ginhttpcontroller"
	auth "github.com/adityafarizki/vpn-gate-pki/oidcauth"
	"github.com/adityafarizki/vpn-gate-pki/s3storage"
	"github.com/adityafarizki/vpn-gate-pki/user"
	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
	"github.com/adityafarizki/vpn-gate-pki/vpnmanager"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
)

var ginLambda *ginadapter.GinLambda

func main() {
	ginController, err := bootstrap()
	if err != nil {
		fmt.Println("Error occured during bootstrap: " + err.Error())
	}

	if vpn.Config.DeploymentEnv == "lambda" {
		ginLambda = ginadapter.New(ginController.Router)
		lambda.Start(Handler)
	} else {
		ginController.Router.Run()
	}
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// If no name is provided in the HTTP request body, throw an error
	return ginLambda.ProxyWithContext(ctx, req)
}

func bootstrap() (*controller.GinHttpController, error) {
	appConfig, err := config.ConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	authInstance, err := auth.NewGoogleOidcAuth(&auth.GoogleOidcAuthConfig{
		AuthUrl:      appConfig.OidcAuthUrl,
		ClientId:     appConfig.OidcClientId,
		ClientSecret: appConfig.OidcClientSecret,
		TokenUrl:     appConfig.OidcTokenUrl,
		CertUrl:      appConfig.OidcTokenUrl,
		RedirectUrl:  appConfig.OidcRedirectUrl,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	s3Storage, err := s3storage.NewS3Storage(appConfig.StorageBucket)
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	certManager := &certmanager.CertManager{
		CaDirPath:       "/ca",
		UserCertDirPath: "/clients",
		CertStorage:     s3Storage,
	}
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	vpnManager, err := vpnmanager.NewVpnManagerFromStorage(&vpnmanager.NewVpnManagerFromStorageParam{
		Storage:         s3Storage,
		ServerIPAddress: appConfig.VpnIpAddress,
		ConfigBasePath:  "/vpn",
		CertManager:     certManager,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	userService := &user.UserService{
		AdminList:   appConfig.AdminEmailList,
		CertManager: certManager,
	}

	ginController := controller.NewGinHttpController(&controller.NewGinHttpControllerParam{
		AuthInstance: authInstance,
		VpnManager:   vpnManager,
		UserService:  userService,
	})
	if err != nil {
		return nil, fmt.Errorf("error boostrapping app: %w", err)
	}

	return ginController, nil
}
