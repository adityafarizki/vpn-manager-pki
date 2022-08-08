package vpngatepki

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type VPNSettings struct {
	ServerIPAddress string
	TlsCrypt        string
	Template        string
}

func GenerateVPNConfig(name string, cm *CertManager, settings *VPNSettings) (string, error) {
	key, cert, err := cm.GetClientCert(name)
	if err != nil {
		return "", err
	}

	_, ca, err := cm.GetCA()
	if err != nil {
		return "", err
	}

	pemCert := certToPemFormat(cert)
	pemKey := keyToPemFormat(key)
	pemCA := certToPemFormat(ca)
	remoteLine := fmt.Sprintf("remote %s 1194", settings.ServerIPAddress)

	config := fmt.Sprintf(
		"%s\n%s\n<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n<tls-crypt>\n%s\n</tls-crypt>",
		remoteLine,
		settings.Template,
		pemCA,
		pemCert,
		pemKey,
		settings.TlsCrypt,
	)
	return config, nil
}

func certToPemFormat(cert *x509.Certificate) string {
	buff := new(bytes.Buffer)
	pemblock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pem.Encode(buff, pemblock)
	return buff.String()
}

func keyToPemFormat(key *rsa.PrivateKey) string {
	buff := new(bytes.Buffer)
	pemblock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	pem.Encode(buff, pemblock)
	return buff.String()
}
