package oidcauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func getJwkSetAuthKeys(jwkSetUrl string) (map[string]*rsa.PublicKey, error) {
	client := http.DefaultClient
	req, err := http.NewRequest("GET", jwkSetUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("error building jwks request: %s", err)
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching jwks: %s", err)
	}

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error fetching jwks: %s", err)
	}
	defer response.Body.Close()

	set, err := jwk.Parse(respBody)
	if err != nil {
		return nil, fmt.Errorf("error parsing jwks: %s", err)
	}

	authKeys := make(map[string]*rsa.PublicKey, set.Len())
	for it := set.Iterate(context.TODO()); it.Next(context.TODO()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{}
		if err := key.Raw(&rawkey); err != nil {
			return nil, fmt.Errorf("error parsing jwks: %s", err)
		}

		rsa, ok := rawkey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("error parsing jwks: %s", err)
		}

		authKeys[key.KeyID()] = rsa
	}

	return authKeys, err
}

func getCertsAuthKeys(certUrl string) (map[string]*rsa.PublicKey, error) {
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
