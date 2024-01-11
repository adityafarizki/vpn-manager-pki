package oidcauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/adityafarizki/vpn-gate-pki/user"
	"github.com/golang-jwt/jwt"
)

func (oAuth *OidcAuthService) GetAuthUrl() string {
	scopeParam := ""
	for _, scope := range oAuth.Scopes {
		scopeParam += fmt.Sprintf("&scope=%s", scope)
	}

	return fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s&response_type=%s%s",
		oAuth.AuthUrl,
		oAuth.ClientId,
		oAuth.RedirectUrl,
		"code",
		scopeParam,
	)
}

func (oAuth *OidcAuthService) AuthenticateJwt(token string) (*user.User, error) {
	parsedJwt, err := oAuth.parseJwt(token)
	if err != nil {
		return nil, fmt.Errorf("authenticating JWT error: %w", err)
	}

	tokenClaims, ok := parsedJwt.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("authenticating JWT error: Parsing token claims error")
	}

	err = tokenClaims.Valid()
	if err != nil {
		return nil, fmt.Errorf("authenticating JWT error: %w", err)
	}

	return &user.User{Email: tokenClaims["email"].(string)}, nil
}

func (oAuth *OidcAuthService) AuthenticateAuthCode(authCode string) (*jwt.Token, error) {
	client := http.DefaultClient
	form := url.Values{}
	form.Add("client_id", oAuth.ClientId)
	form.Add("client_secret", oAuth.ClientSecret)
	form.Add("grant_type", "authorization_code")
	form.Add("code", authCode)
	form.Add("redirect_uri", oAuth.RedirectUrl)
	// body, err := json.Marshal(gin.H{
	// 	"client_id":     oAuth.ClientId,
	// 	"client_secret": oAuth.ClientSecret,
	// 	"grant_type":    "authorization_code",
	// 	"code":          authCode,
	// 	"redirect_uri":  oAuth.RedirectUrl,
	// })
	// if err != nil {
	// 	return nil, fmt.Errorf("parsing auth parameter error: %w", err)
	// }

	req, err := http.NewRequest("POST", oAuth.TokenUrl, bytes.NewBuffer([]byte(form.Encode())))
	if err != nil {
		return nil, fmt.Errorf("forming jwt request error: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting jwt error: %w", err)
	}
	defer response.Body.Close()

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt response: %w", err)
	}

	respToken := map[string]string{}
	json.Unmarshal(respBody, &respToken)

	userToken, err := oAuth.parseJwt(respToken["access_token"])
	if err != nil {
		return nil, fmt.Errorf("parsing jwt error: %w", err)
	}

	return userToken, nil
}

func (oAuth *OidcAuthService) parseJwt(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		keyId := token.Header["kid"].(string)
		pubKey := oAuth.AuthKeys[keyId]

		if pubKey == nil {
			return nil, fmt.Errorf("parsing JWT error: JWT pubkey not found")
		} else {
			return pubKey, nil
		}
	})
}
