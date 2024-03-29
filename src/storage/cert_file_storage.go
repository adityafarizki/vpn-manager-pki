package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

type CertFileStorage struct {
	CAFileDir     string
	ClientCertDir string
	ca            *x509.Certificate
	caPrivKey     *rsa.PrivateKey
}

func NewCertFileStorage(caFileDir string, clientCertDir string) (*CertFileStorage, error) {
	err := os.MkdirAll(caFileDir, 0755)
	if err != nil {
		return nil, err
	}

	err = os.MkdirAll(clientCertDir, 0755)
	if err != nil {
		return nil, err
	}

	cs := &CertFileStorage{
		CAFileDir:     caFileDir,
		ClientCertDir: clientCertDir,
	}

	return cs, nil
}

func (cs *CertFileStorage) GetCertList() ([]string, error) {
	objList, err := cs.listFiles(cs.ClientCertDir)
	if err != nil {
		return nil, err
	}

	certList := []string{}
	suffixLength := len("_cert.pem")
	prefixLength := len(cs.ClientCertDir + "/")
	for _, obj := range objList {
		keyLen := len(obj)
		if keyLen < prefixLength+suffixLength {
			continue
		}

		left := keyLen - suffixLength
		right := keyLen

		if obj[left:right] == "_cert.pem" {
			certList = append(certList, obj[prefixLength:left])
		}
	}

	return certList, nil
}

func (c *CertFileStorage) GetTlsCrypt() (string, error) {
	tls_crypt, err := ioutil.ReadFile(c.CAFileDir + "/tls_crypt.pem")
	return string(tls_crypt), err
}

func (c *CertFileStorage) GetVpnTemplate() (string, error) {
	template, err := ioutil.ReadFile(c.CAFileDir + "/template.ovpn")
	return string(template), err
}

func (c *CertFileStorage) SaveCert(privKey *rsa.PrivateKey, cert *x509.Certificate) error {
	name := cert.Subject.CommonName

	certPemFileDir := fmt.Sprintf("%s/%s_cert.pem", c.ClientCertDir, name)
	err := c.saveCertFile(certPemFileDir, cert)
	if err != nil {
		return err
	}

	pemFileDir := fmt.Sprintf("%s/%s_priv.pem", c.ClientCertDir, name)
	err = c.savePrivateKeyFile(pemFileDir, privKey)
	if err != nil {
		return err
	}

	return nil
}

func (cs *CertFileStorage) GetCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	if cs.ca != nil && cs.caPrivKey != nil {
		return cs.caPrivKey, cs.ca, nil
	}

	certPath := cs.GetCACertPath()
	cert, err := cs.readCertFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	keyPath := cs.GetCAKeyPath()
	privkey, err := cs.readPrivateKeyFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	cs.ca = cert
	cs.caPrivKey = privkey
	return privkey, cert, nil
}

func (cs *CertFileStorage) SaveCA(privkey *rsa.PrivateKey, ca *x509.Certificate) error {
	cs.ca = ca
	cs.caPrivKey = privkey

	certPath := cs.GetCACertPath()
	err := cs.saveCertFile(certPath, ca)
	if err != nil {
		return err
	}

	keyPath := cs.GetCAKeyPath()
	err = cs.savePrivateKeyFile(keyPath, privkey)
	if err != nil {
		return err
	}

	return nil
}

func (cs *CertFileStorage) GetCert(name string) (*rsa.PrivateKey, *x509.Certificate, error) {
	certPath, keyPath := cs.GetClientCertPath(name)

	cert, err := cs.readCertFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	privkey, err := cs.readPrivateKeyFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	return privkey, cert, nil
}

func (cs *CertFileStorage) GetClientCertPath(name string) (certPath string, keyPath string) {
	certPath = fmt.Sprintf("%s/%s_cert.pem", cs.ClientCertDir, name)
	keyPath = fmt.Sprintf("%s/%s_priv.pem", cs.ClientCertDir, name)

	return certPath, keyPath
}

func (cs *CertFileStorage) GetCACertPath() string {
	return fmt.Sprintf("%s/cert.pem", cs.CAFileDir)
}

func (cs *CertFileStorage) GetCAKeyPath() string {
	return fmt.Sprintf("%s/priv.pem", cs.CAFileDir)
}

func (cs *CertFileStorage) GetCACRLPath() string {
	return fmt.Sprintf("%s/crl.pem", cs.CAFileDir)
}

func (c *CertFileStorage) readCertFile(certPath string) (*x509.Certificate, error) {
	rawCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	pemCert, _ := pem.Decode(rawCert)

	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (cs *CertFileStorage) saveCertFile(certPath string, cert *x509.Certificate) error {
	certpemfile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certpemfile.Close()

	certpem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	err = pem.Encode(certpemfile, certpem)
	if err != nil {
		return err
	}

	return nil
}

func (c *CertFileStorage) readPrivateKeyFile(keyPath string) (*rsa.PrivateKey, error) {
	rawKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	pemKey, _ := pem.Decode(rawKey)

	privkey, err := x509.ParsePKCS8PrivateKey(pemKey.Bytes)
	if err != nil {
		return nil, err
	}

	return privkey.(*rsa.PrivateKey), nil
}

func (cs *CertFileStorage) savePrivateKeyFile(keypath string, privkey *rsa.PrivateKey) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return err
	}

	pemFile, err := os.Create(keypath)
	if err != nil {
		return err
	}

	defer pemFile.Close()
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	err = pem.Encode(pemFile, pemkey)
	if err != nil {
		return err
	}

	return nil
}

func (c *CertFileStorage) listFiles(path string) ([]string, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	fileList := []string{}
	for _, file := range files {
		fileList = append(fileList, file.Name())
	}

	return fileList, nil
}

func (c *CertFileStorage) SaveCRL(certs []pkix.RevokedCertificate) error {
	caPrivkey, ca, err := c.GetCA()
	if err != nil {
		return err
	}

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader, &x509.RevocationList{Number: big.NewInt(100), RevokedCertificates: certs}, ca, caPrivkey,
	)
	if err != nil {
		return err
	}

	pemFileDir := fmt.Sprintf("%s/crl.pem", c.CAFileDir)
	pemFile, _ := os.Create(pemFileDir)
	defer pemFile.Close()
	var pemblock = &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	}
	err = pem.Encode(pemFile, pemblock)

	return err
}

func (c *CertFileStorage) GetCRL() ([]pkix.RevokedCertificate, error) {
	crlPath := fmt.Sprintf("%s/crl.pem", c.CAFileDir)
	rawCrl, err := ioutil.ReadFile(crlPath)
	if err != nil {
		return nil, err
	}

	if len(rawCrl) == 0 {
		return []pkix.RevokedCertificate{}, nil
	}

	pemCrl, _ := pem.Decode(rawCrl)
	crl, err := x509.ParseCRL(pemCrl.Bytes)
	if err != nil {
		return nil, err
	}

	return crl.TBSCertList.RevokedCertificates, nil
}
