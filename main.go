package vpngatepki

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"

	"github.com/adityafarizki/vpn-gate-pki/storage"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
)

var cm *CertManager
var vpnSettings *VPNSettings
var Config *AppConfig
var authCerts map[string]*rsa.PublicKey

type User struct {
	Email string
	Sub   string
}

var ginLambda *ginadapter.GinLambda

func main() {
	err := Bootstrap()
	if err != nil {
		fmt.Println("Error occured during bootstrap: " + err.Error())
	}

	router := BuildGinRouter()
	if Config.DeploymentEnv == "lambda" {
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

func Bootstrap() error {
	var err error
	Config = loadConfig()
	authCerts, err = FetchAuthCerts(Config.CertUrl)
	if err != nil {
		return errors.New("Initializing auth cert error: " + err.Error())
	}

	cs, err := storage.NewCertAWSStorage("ca", "clients", Config.S3BucketName)
	if err != nil {
		fmt.Println()
		return errors.New("Intializing storage error: " + err.Error())
	}

	cm = &CertManager{certStorage: cs}

	vpnSettings, err = initializeVPNSettings(cm)
	if err != nil {
		return errors.New("Intializing vpn settings error: " + err.Error())
	}

	return nil
}

func initializeVPNSettings(cm *CertManager) (*VPNSettings, error) {
	vpnTemplate, err := cm.GetVpnTemplate()
	if err != nil {
		return nil, err
	}

	tlsCrypt, err := cm.GetTlsCrypt()
	if err != nil {
		return nil, err
	}

	vpnSettings = &VPNSettings{
		ServerIPAddress: Config.VPNIPAdress,
		Template:        vpnTemplate,
		TlsCrypt:        tlsCrypt,
	}

	return vpnSettings, nil
}

func FetchAuthCerts(certUrl string) (map[string]*rsa.PublicKey, error) {
	client := http.DefaultClient
	req, err := http.NewRequest("GET", certUrl, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	certs := map[string]string{}
	json.Unmarshal(respBody, &certs)

	result := map[string]*rsa.PublicKey{}
	for key, element := range certs {
		certBlock, _ := pem.Decode([]byte(element))
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}
		pubKey := cert.PublicKey.(*rsa.PublicKey)

		result[key] = pubKey
	}

	return result, nil
}

func GetAuthUrl() string {
	return fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s",
		Config.AuthUrl,
		Config.ClientId,
		Config.RedirectUrl,
		"code",
		"https://www.googleapis.com/auth/userinfo.email",
	)
}

func GetTokenFromAuthCode(authCode string) (*jwt.Token, error) {
	userToken, _ := getUserToken(authCode)
	token, err := parseJWTToken(userToken["id_token"])

	return token, err
}

func parseJWTToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		keyId := token.Header["kid"].(string)
		pubKey := authCerts[keyId]

		if pubKey == nil {
			return nil, errors.New("token key id is not found")
		} else {
			return pubKey, nil
		}
	})
}

func getUserToken(authCode string) (map[string]string, error) {
	client := http.DefaultClient
	body, err := json.Marshal(gin.H{
		"client_id":     Config.ClientId,
		"client_secret": Config.ClientSecret,
		"grant_type":    "authorization_code",
		"code":          authCode,
		"redirect_uri":  Config.RedirectUrl,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", Config.TokenUrl, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	userToken := map[string]string{}
	json.Unmarshal(respBody, &userToken)

	return userToken, nil
}

func AuthenticateUserToken(token string) (*User, error) {
	parsedToken, err := parseJWTToken(token)
	if err != nil {
		return nil, err
	}

	tokenClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("parsing token claims error")
	}

	user := &User{}

	if email, isString := tokenClaims["email"].(string); isString {
		user.Email = email
	} else {
		return nil, errors.New("invalid email claims in token")
	}

	if sub, isString := tokenClaims["sub"].(string); isString {
		user.Sub = sub
	} else {
		return nil, errors.New("invalid sub claims in token")
	}

	return user, nil
}

func GetUserVPNConfig(user *User) (string, error) {
	_, _, err := cm.GetClientCert(user.Email)

	if err != nil {
		switch err.(type) {
		case *fs.PathError:
			cm.CreateNewClientCert(user.Email)
		default:
			return "", nil
		}
	}

	return GenerateVPNConfig(user.Email, cm, vpnSettings)
}

func IsUserAdmin(user *User) bool {
	for _, admin := range Config.AdminList {
		if user.Email == admin {
			return true
		}
	}

	return false
}

func GetUsersList(user *User) ([]User, error) {
	if !IsUserAdmin(user) {
		return nil, errors.New("user is unauthorized to lists registered users")
	}

	userEmails, err := cm.GetClientList()
	if err != nil {
		return nil, err
	}

	users := []User{}
	for _, email := range userEmails {
		users = append(users, User{Email: email})
	}

	return users, nil
}

func RevokeUserAccess(requester *User, target string) error {
	_, clientCert, err := cm.GetClientCert(target)
	if err != nil {
		return err
	}

	err = cm.RevokeCert(clientCert)
	if err != nil {
		return err
	}

	return nil
}

func InitPKI() error {
	return cm.InitPKI()
}
