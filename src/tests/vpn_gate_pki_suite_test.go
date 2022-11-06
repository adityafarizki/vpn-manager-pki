package vpngatepki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
)

var jwtPubKey *rsa.PublicKey
var jwtPrivKey *rsa.PrivateKey
var jwtKeyId string

func TestVpnGatePki(t *testing.T) {
	vpn.Bootstrap()
	vpn.InitPKI()
	err := setJwtKeys()
	if err != nil {
		fmt.Println(err)
	}

	RegisterFailHandler(Fail)
	RunSpecs(t, "VpnGatePki Suite")

	cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
}

func setJwtKeys() error {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	publickey := &privatekey.PublicKey

	jwtPrivKey = privatekey
	jwtPubKey = publickey
	jwtKeyId = randomString(30)

	vpn.AuthCerts[jwtKeyId] = jwtPubKey

	return nil
}
