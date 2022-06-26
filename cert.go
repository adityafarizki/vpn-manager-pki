package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type CertInfo struct {
	CommonName string
	IsCA       bool
}

type CertStorage interface {
	SaveCRL([]pkix.RevokedCertificate) error
	GetCRL() ([]pkix.RevokedCertificate, error)
	SaveCert(privatekey *rsa.PrivateKey, cert *x509.Certificate) error
	GetCert(name string) (*rsa.PrivateKey, *x509.Certificate, error)
	GetCA() (*rsa.PrivateKey, *x509.Certificate, error)
	GetTlsCrypt() (string, error)
	GetVpnTemplate() (string, error)
	GetCertList() ([]string, error)
}

type CertManager struct {
	certStorage CertStorage
}

func (cm *CertManager) GetClientList() ([]string, error) {
	return cm.certStorage.GetCertList()
}

func (cm *CertManager) GetClientCert(name string) (*rsa.PrivateKey, *x509.Certificate, error) {
	return cm.certStorage.GetCert(name)
}

func (cm *CertManager) GetVpnTemplate() (string, error) {
	return cm.certStorage.GetVpnTemplate()
}

func (cm *CertManager) GetCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	return cm.certStorage.GetCA()
}

func (cm *CertManager) GetTlsCrypt() (string, error) {
	return cm.certStorage.GetTlsCrypt()
}

func (cm *CertManager) CreateNewClientCert(name string) (*x509.Certificate, error) {
	caPrivKey, ca, err := cm.certStorage.GetCA()
	if err != nil {
		return nil, err
	}

	certTemplate, err := getCertTemplate(&CertInfo{CommonName: name, IsCA: false})
	if err != nil {
		return nil, err
	}

	privateKey, publicKey, err := genKeyPair()
	if err != nil {
		return nil, err
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, publicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	clientCert, err := x509.ParseCertificate(clientCertBytes)
	if err != nil {
		return nil, err
	}

	err = cm.certStorage.SaveCert(privateKey, clientCert)
	if err != nil {
		return nil, err
	}

	return clientCert, nil
}

func (cm *CertManager) RevokeCert(cert *x509.Certificate) error {
	crl, err := cm.certStorage.GetCRL()
	if err != nil {
		return err
	}

	newRevokedCert := &pkix.RevokedCertificate{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
	}
	revokedCerts := append(crl, *newRevokedCert)
	err = cm.certStorage.SaveCRL(revokedCerts)

	return err
}

func InitPKI(dirname string) error {
	ca, err := getCertTemplate(&CertInfo{CommonName: "PersonalCA", IsCA: true})
	if err != nil {
		return err
	}

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	publickey := &privatekey.PublicKey

	var parent = ca
	cert, err := x509.CreateCertificate(
		rand.Reader, ca, parent, publickey, privatekey,
	)
	if err != nil {
		return err
	}

	isDirExists, err := os.Stat(dirname)
	if err != nil || !isDirExists.IsDir() {
		err := os.Mkdir(dirname, os.FileMode(0700))
		if err != nil {
			return err
		}
	}

	certPemFileDir := fmt.Sprintf("%s/cert.pem", dirname)
	certpemfile, _ := os.Create(certPemFileDir)
	defer certpemfile.Close()
	certpem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	pem.Encode(certpemfile, certpem)

	pubPemFileDir := fmt.Sprintf("%s/pub.pem", dirname)
	pubpemfile, _ := os.Create(pubPemFileDir)
	defer certpemfile.Close()
	pubkeyBytes, _ := x509.MarshalPKIXPublicKey(publickey)
	pubpem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyBytes,
	}
	pem.Encode(pubpemfile, pubpem)

	// this will create plain text PEM file.
	pemFileDir := fmt.Sprintf("%s/priv.pem", dirname)
	pemFile, _ := os.Create(pemFileDir)
	defer pemFile.Close()
	privkeyBytes, _ := x509.MarshalPKCS8PrivateKey(privatekey)
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privkeyBytes,
	}
	pem.Encode(pemFile, pemkey)

	pemCrlDir := fmt.Sprintf("%s/crl.pem", dirname)
	pemCrlFile, _ := os.Create(pemCrlDir)
	defer pemCrlFile.Close()
	// var pemblock = &pem.Block{
	// 	Type:  "X509 CRL",
	// 	Bytes: []byte{},
	// }
	// err = pem.Encode(pemCrlFile, pemblock)
	// if err != nil {
	// 	return err
	// }

	return nil
}

func genKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publickey := &privatekey.PublicKey

	return privatekey, publickey, nil
}

func getCertTemplate(info *CertInfo) (*x509.Certificate, error) {
	skId := make([]byte, 32)
	rand.Read(skId)

	serialNumber, err := generateRandomBigInt()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		IsCA:                  info.IsCA,
		BasicConstraintsValid: true,
		SubjectKeyId:          skId,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Country:      []string{"ID"},
			Organization: []string{"Personal"},
			CommonName:   info.CommonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(100, 0, 0),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageCodeSigning,
		},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Issuer: pkix.Name{
			Country:            []string{"AA"},
			Organization:       []string{"Personal"},
			OrganizationalUnit: []string{"Cloud"},
			Locality:           []string{"Local"},
			Province:           []string{"Local"},
			StreetAddress:      nil,
			PostalCode:         nil,
			SerialNumber:       serialNumber.String(),
			CommonName:         "Personal",
			Names:              nil,
			ExtraNames:         nil,
		},
	}

	return &template, nil
}

func generateRandomBigInt() (*big.Int, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(160), nil)
	max.Sub(max, big.NewInt(1))

	min := new(big.Int)
	min.Exp(big.NewInt(2), big.NewInt(158), nil)

	maxRand := new(big.Int)
	maxRand.Sub(max, min)

	n, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		return big.NewInt(0), err
	}

	val := new(big.Int)
	val.Add(min, n)

	return val, nil
}
