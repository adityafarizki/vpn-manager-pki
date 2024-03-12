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
}

type IUserDataStorage interface {
	GetFile(path string) ([]byte, error)
	SaveFile(path string, data []byte) error
	ListDir(path string) ([]string, error)
	DeleteFile(path string) error
}
