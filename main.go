package main

import (
	"bytes"
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
)

var cm *CertManager
var vpnSettings *VPNSettings
var appConfig AppConfig
var authCerts map[string]*rsa.PublicKey

type User struct {
	Email string
	Sub   string
}

func testCertManager() {
	// if err := InitPKI("certs"); err != nil {
	// 	fmt.Printf("Init PKI error: %s\n", err)
	// }

	cs, err := storage.NewCertAWSStorage(
		"ca", "clients", "vpn-bucket-881287946390-ap-southeast-1",
	)
	if err != nil {
		fmt.Printf("Initializing AWS storage error: %s\n", err)
		return
	}

	cm = &CertManager{
		certStorage: cs,
	}

	vpnTemplate, err := cm.GetVpnTemplate()
	if err != nil {
		fmt.Printf("Getting VPN Template Error: %s\n", err)
		return
	}

	tlsCrypt, err := cm.GetTlsCrypt()
	if err != nil {
		fmt.Printf("Getting TLS Crypt Error: %s\n", err)
		return
	}

	vpnSettings = &VPNSettings{
		ServerIPAddress: "34.142.227.244",
		Template:        vpnTemplate,
		TlsCrypt:        tlsCrypt,
	}

	_, err = cm.CreateNewClientCert("adot")
	if err != nil {
		fmt.Printf("Generating client cert error: %s\n", err)
	}

	config, err := GenerateVPNConfig("adot", cm, vpnSettings)
	if err != nil {
		fmt.Printf("Generating VPN config error: %s\n", err)
	}

	err = ioutil.WriteFile("config.ovpn", []byte(config), fs.FileMode(0755))
	if err != nil {
		fmt.Printf("Writing VPN config error: %s\n", err)
	}
}

func main() {
	var err error
	appConfig = loadConfig()
	authCerts, err = fetchAuthCerts(appConfig.CertUrl)
	if err != nil {
		fmt.Println("Initializing auth cert error: ", err)
		return
	}

	cs, err := storage.NewCertAWSStorage("ca", "clients", appConfig.S3BucketName)
	if err != nil {
		fmt.Println("Intializing storage error: ", err)
		return
	}

	cm = &CertManager{certStorage: cs}

	vpnSettings, err = initializeVPNSettings(cm)
	if err != nil {
		fmt.Println("Intializing vpn settings error: ", err)
		return
	}

	if appConfig.DeploymentEnv != "lambda" {
		runGinServer()
	}
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
		ServerIPAddress: appConfig.VPNIPAdress,
		Template:        vpnTemplate,
		TlsCrypt:        tlsCrypt,
	}

	return vpnSettings, nil
}

func fetchAuthCerts(certUrl string) (map[string]*rsa.PublicKey, error) {
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

func getAuthUrl() string {
	return fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s",
		appConfig.AuthUrl,
		appConfig.ClientId,
		appConfig.RedirectUrl,
		"code",
		"https://www.googleapis.com/auth/userinfo.email",
	)
}

func getTokenFromAuthCode(authCode string) (*jwt.Token, error) {
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
		"client_id":     appConfig.ClientId,
		"client_secret": appConfig.ClientSecret,
		"grant_type":    "authorization_code",
		"code":          authCode,
		"redirect_uri":  appConfig.RedirectUrl,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", appConfig.TokenUrl, bytes.NewBuffer(body))
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

func authenticateUserToken(token string) (*User, error) {
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

func getUserVPNConfig(user *User) (string, error) {
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

func isUserAdmin(user *User) bool {
	for _, admin := range appConfig.AdminList {
		if user.Email == admin {
			return true
		}
	}

	return false
}

func getUsersList(user *User) ([]User, error) {
	if !isUserAdmin(user) {
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

func revokeUserAccess(requester *User, target string) error {
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
