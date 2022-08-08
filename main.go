package main

import (
	"context"
	"fmt"

	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
)

var ginLambda *ginadapter.GinLambda

func main() {
	err := vpn.Bootstrap()
	if err != nil {
		fmt.Println("Error occured during bootstrap: " + err.Error())
	}

	router := vpn.BuildGinRouter()
	if vpn.Config.DeploymentEnv == "lambda" {
		ginLambda = ginadapter.New(router)
		lambda.Start(Handler)
	} else {
		router.Run()
	}
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// If no name is provided in the HTTP request body, throw an error
	return ginLambda.ProxyWithContext(ctx, req)
}
