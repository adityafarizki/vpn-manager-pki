package vpngatepki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
	SaveCA(*rsa.PrivateKey, *x509.Certificate) error
	GetCA() (*rsa.PrivateKey, *x509.Certificate, error)
	GetTlsCrypt() (string, error)
	GetVpnTemplate() (string, error)
	GetCertList() ([]string, error)
	MarkRevoked(*x509.Certificate) error
}

type CertManager struct {
	CertStorage CertStorage
}

func (cm *CertManager) GetClientList() ([]string, error) {
	return cm.CertStorage.GetCertList()
}

func (cm *CertManager) GetClientCert(name string) (*rsa.PrivateKey, *x509.Certificate, error) {
	return cm.CertStorage.GetCert(name)
}

func (cm *CertManager) GetVpnTemplate() (string, error) {
	return cm.CertStorage.GetVpnTemplate()
}

func (cm *CertManager) GetCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	return cm.CertStorage.GetCA()
}

func (cm *CertManager) GetTlsCrypt() (string, error) {
	return cm.CertStorage.GetTlsCrypt()
}

func (cm *CertManager) CreateNewClientCert(name string) (*x509.Certificate, error) {
	caPrivKey, ca, err := cm.CertStorage.GetCA()
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

	err = cm.CertStorage.SaveCert(privateKey, clientCert)
	if err != nil {
		return nil, err
	}

	return clientCert, nil
}

func (cm *CertManager) RevokeCert(cert *x509.Certificate) error {
	crl, err := cm.CertStorage.GetCRL()
	if err != nil {
		return err
	}

	newRevokedCert := &pkix.RevokedCertificate{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
	}
	revokedCerts := append(crl, *newRevokedCert)
	err = cm.CertStorage.SaveCRL(revokedCerts)
	if err != nil {
		return err
	}

	err = cm.CertStorage.MarkRevoked(cert)

	return err
}

func (cm *CertManager) InitPKI() error {
	caTemplate, err := getCertTemplate(&CertInfo{CommonName: "PersonalCA", IsCA: true})
	if err != nil {
		return err
	}

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	publickey := &privatekey.PublicKey

	parent := caTemplate
	cert, err := x509.CreateCertificate(
		rand.Reader, caTemplate, parent, publickey, privatekey,
	)
	if err != nil {
		return err
	}

	ca, err := x509.ParseCertificate(cert)
	if err != nil {
		return err
	}

	err = cm.CertStorage.SaveCA(privatekey, ca)
	if err != nil {
		return err
	}

	err = cm.CertStorage.SaveCRL([]pkix.RevokedCertificate{})
	if err != nil {
		return err
	}

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
