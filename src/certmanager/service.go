package certmanager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	cmerr "github.com/adityafarizki/vpn-gate-pki/commonerrors"
)

func (cm *CertManager) GetCert(commonName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPath := cm.getCertPath(commonName)
	keyPath := cm.getKeyPath(commonName)

	certBinary, err := cm.CertStorage.GetFile(certPath)
	if err != nil {
		if serr, ok := err.(cmerr.NotFoundError); ok {
			errMessage := fmt.Sprintf("GetCert error: %s", serr.Error())
			return nil, nil, cmerr.NotFoundError{Message: errMessage}
		}
		return nil, nil, fmt.Errorf("GetCert error: %w", err)
	}

	keyBinary, err := cm.CertStorage.GetFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("GetCert error: %w", err)
	}

	cert, err := cm.PemToCert(certBinary)
	if err != nil {
		return nil, nil, fmt.Errorf("GetCert error: %w", err)
	}

	key, err := cm.PemToKey(keyBinary)
	if err != nil {
		return nil, nil, fmt.Errorf("GetCert error: %w", err)
	}

	return cert, key, nil
}

func (cm *CertManager) GenerateCert(commonName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	ca, caKey, err := cm.GetRootCert()
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	certTemplate, err := cm.getCertTemplate(false, commonName)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	privateKey, publicKey, err := cm.genKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, publicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	certPath := cm.getCertPath(commonName)
	certPem, err := cm.CertToPem(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	err = cm.CertStorage.SaveFile(certPath, certPem)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	keyPath := cm.getKeyPath(commonName)
	keyPem, err := cm.KeyToPem(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	err = cm.CertStorage.SaveFile(keyPath, keyPem)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateCert error: %w", err)
	}

	return cert, privateKey, nil
}

func (cm *CertManager) RevokeCert(userCert *x509.Certificate) error {
	crl, err := cm.GetCrl()
	if err != nil {
		return fmt.Errorf("Revoke cert error: %w", err)
	}

	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(userCert.SerialNumber) == 0 {
			return nil
		}
	}

	newRevokedCert := &pkix.RevokedCertificate{
		SerialNumber:   userCert.SerialNumber,
		RevocationTime: time.Now(),
	}
	crl.TBSCertList.RevokedCertificates = append(crl.TBSCertList.RevokedCertificates, *newRevokedCert)
	err = cm.SaveCrl(crl)
	if err != nil {
		return fmt.Errorf("Revoke cert error: %w", err)
	}

	return nil
}

func (cm *CertManager) IsCertRevoked(userCert *x509.Certificate) (bool, error) {
	crl, err := cm.GetCrl()
	if err != nil {
		return true, fmt.Errorf("check IsRevoked error: %w", err)
	}

	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(userCert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

func (cm *CertManager) GetCrl() (*pkix.CertificateList, error) {
	crlPath := cm.getCrlPath()
	crlBinary, err := cm.CertStorage.GetFile(crlPath)
	if err != nil {
		return nil, fmt.Errorf("Get CRL error: %w", err)
	}

	crlPemBlock, _ := pem.Decode(crlBinary)
	crl, err := x509.ParseCRL(crlPemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Get CRL error: %w", err)
	}

	return crl, nil
}

func (cm *CertManager) GetRevokedList() ([]string, error) {
	revokedList, err := cm.CertStorage.ListDir(cm.getRevokedCertNamePath())
	if err != nil {
		return nil, fmt.Errorf("get revoked list error: %w", err)
	}

	return revokedList, nil
}

func (cm *CertManager) SaveCrl(crl *pkix.CertificateList) error {
	ca, caKey, err := cm.GetRootCert()
	if err != nil {
		return fmt.Errorf("Save CRL error: %w", err)
	}

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader, &x509.RevocationList{
			Number:              big.NewInt(100),
			RevokedCertificates: crl.TBSCertList.RevokedCertificates,
		},
		ca,
		caKey,
	)
	if err != nil {
		return fmt.Errorf("Save CRL error: %w", err)
	}

	var crlPemBlock = &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	}
	var crlPemBytesBuffer bytes.Buffer
	err = pem.Encode(io.Writer(&crlPemBytesBuffer), crlPemBlock)
	if err != nil {
		return fmt.Errorf("Save CRL error: %w", err)
	}

	err = cm.CertStorage.SaveFile(cm.getCrlPath(), crlPemBytesBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("Save CRL error: %w", err)
	}

	return nil
}

func (cm *CertManager) ListCertsCommonName() ([]string, error) {
	commonNameList, err := cm.CertStorage.ListDir(cm.UserCertDirPath + "/")
	if err != nil {
		return nil, fmt.Errorf("List certs common name error: %w", err)
	}

	return commonNameList, nil
}

func (cm *CertManager) PemToCert(pemBinary []byte) (*x509.Certificate, error) {
	pemCert, _ := pem.Decode(pemBinary)
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (cm *CertManager) PemToKey(pemBinary []byte) (*rsa.PrivateKey, error) {
	pemKey, _ := pem.Decode(pemBinary)
	privkey, err := x509.ParsePKCS8PrivateKey(pemKey.Bytes)
	if err != nil {
		return nil, err
	}

	return privkey.(*rsa.PrivateKey), nil
}

func (cm *CertManager) CertToPem(cert *x509.Certificate) ([]byte, error) {
	certPemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	var certPemBytesBuffer bytes.Buffer
	err := pem.Encode(io.Writer(&certPemBytesBuffer), certPemBlock)
	if err != nil {
		return nil, fmt.Errorf("Converting Cert To Pem error: %w", err)
	}

	return certPemBytesBuffer.Bytes(), nil
}

func (cm *CertManager) KeyToPem(privkey *rsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("Converting Key To Pem error: %w", err)
	}

	keyPemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	var keyPemBytesBuffer bytes.Buffer
	err = pem.Encode(io.Writer(&keyPemBytesBuffer), keyPemBlock)
	if err != nil {
		return nil, fmt.Errorf("Converting Key To Pem error: %w", err)
	}

	return keyPemBytesBuffer.Bytes(), nil
}

func (cm *CertManager) getCertPath(commonName string) string {
	return fmt.Sprintf("%s/%s/cert.pem", cm.UserCertDirPath, commonName)
}

func (cm *CertManager) getKeyPath(commonName string) string {
	return fmt.Sprintf("%s/%s/key.pem", cm.UserCertDirPath, commonName)
}

func (cm *CertManager) getCrlPath() string {
	return fmt.Sprintf("%s/crl.pem", cm.CaDirPath)
}

func (cm *CertManager) getRevokedCertNamePath() string {
	return "revokedClients/"
}

func (cm *CertManager) handleError(err error) error {
	return err
}

func (cm *CertManager) GetRootCert() (*x509.Certificate, *rsa.PrivateKey, error) {
	caCertPath := fmt.Sprintf("%s/cert.pem", cm.CaDirPath)
	caKeyPath := fmt.Sprintf("%s/priv.pem", cm.CaDirPath)

	certBinary, err := cm.CertStorage.GetFile(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("GetRootCert error: %w", err)
	}

	keyBinary, err := cm.CertStorage.GetFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("GetRootCert error: %w", err)
	}

	cert, err := cm.PemToCert(certBinary)
	if err != nil {
		return nil, nil, fmt.Errorf("GetRootCert error: %w", err)
	}

	key, err := cm.PemToKey(keyBinary)
	if err != nil {
		return nil, nil, fmt.Errorf("GetRootCert error: %w", err)
	}

	return cert, key, nil
}

func (cm *CertManager) getCertTemplate(isCA bool, commonName string) (*x509.Certificate, error) {
	skId := make([]byte, 32)
	rand.Read(skId)

	serialNumber, err := cm.generateRandomBigInt()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		SubjectKeyId:          skId,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Country:      []string{"ID"},
			Organization: []string{"Personal"},
			CommonName:   commonName,
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

func (cm *CertManager) generateRandomBigInt() (*big.Int, error) {
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

func (cm *CertManager) genKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publickey := &privatekey.PublicKey

	return privatekey, publickey, nil
}
