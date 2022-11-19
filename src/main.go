package main

import (
	"context"
	"fmt"

	"github.com/adityafarizki/vpn-gate-pki/config"
	httpcontroller "github.com/adityafarizki/vpn-gate-pki/ginhttpcontroller"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
)

var ginLambda *ginadapter.GinLambda

func main() {
	appConfig, err := config.ConfigFromEnv()
	if err != nil {
		fmt.Println("error occured during bootstrap: " + err.Error())
		return
	}

	ginController, err := httpcontroller.Bootstrap(appConfig)
	if err != nil {
		fmt.Println("error occured during bootstrap: " + err.Error())
		return
	}

	if appConfig.DeploymentEnv == "lambda" {
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
