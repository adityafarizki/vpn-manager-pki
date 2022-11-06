package user

import (
	"crypto/rsa"
	"crypto/x509"
)

type IUserCertManager interface {
	GetCert(commonName string) (*x509.Certificate, *rsa.PrivateKey, error)
	GenerateCert(commonName string) (*x509.Certificate, *rsa.PrivateKey, error)
	RevokeCert(userCert *x509.Certificate) error
	IsCertRevoked(userCert *x509.Certificate) (bool, error)
	ListCertsCommonName() ([]string, error)
}
