package vpngatepki

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

var Config *AppConfig
var AuthCerts map[string]*rsa.PublicKey
var CertMgr *CertManager
var VpnSettings *VPNSettings

func Bootstrap() error {
	var err error
	Config = loadConfig()
	AuthCerts, err = fetchAuthCerts(Config.CertUrl)
	if err != nil {
		return errors.New("Initializing auth cert error: " + err.Error())
	}

	cs, err := storage.NewCertAWSStorage("ca", "clients", Config.S3BucketName)
	if err != nil {
		return errors.New("Intializing storage error: " + err.Error())
	}

	CertMgr = &CertManager{CertStorage: cs}

	VpnSettings, err = initializeVPNSettings(CertMgr)
	if err != nil {
		return errors.New("Intializing vpn settings error: " + err.Error())
	}

	return nil
}

func initializeVPNSettings(CertMgr *CertManager) (*VPNSettings, error) {
	vpnTemplate, err := CertMgr.GetVpnTemplate()
	if err != nil {
		return nil, err
	}

	tlsCrypt, err := CertMgr.GetTlsCrypt()
	if err != nil {
		return nil, err
	}

	VpnSettings = &VPNSettings{
		ServerIPAddress: Config.VPNIPAdress,
		Template:        vpnTemplate,
		TlsCrypt:        tlsCrypt,
	}

	return VpnSettings, nil
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
		Config.AuthUrl,
		Config.ClientId,
		Config.RedirectUrl,
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
		pubKey := AuthCerts[keyId]

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

func handleError(err error) error {
	switch err.(type) {
	case *fs.PathError:
		return &NotFoundError{message: err.Error()}
	default:
		return err
	}
}

func GetUserVPNConfig(user *User) (string, error) {
	_, _, err := CertMgr.GetClientCert(user.Email)

	if err != nil {
		switch err.(type) {
		case *fs.PathError:
			CertMgr.CreateNewClientCert(user.Email)
		default:
			return "", nil
		}
	}

	return GenerateVPNConfig(user.Email, CertMgr, VpnSettings)
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

	userEmails, err := CertMgr.GetClientList()
	if err != nil {
		return nil, err
	}

	users := []User{}
	for _, email := range userEmails {
		users = append(users, User{Email: email})
	}

	return users, nil
}

func RevokeUserAccess(requester *User, targetEmail string) error {
	if !IsUserAdmin(requester) {
		return &UnauthorizedError{message: "user is unauthorized to revoke cert"}
	}
	_, clientCert, err := CertMgr.GetClientCert(targetEmail)
	if err != nil {
		return handleError(err)
	}

	err = CertMgr.RevokeCert(clientCert)
	if err != nil {
		return handleError(err)
	}

	return nil
}

func InitPKI() error {
	return CertMgr.InitPKI()
}
