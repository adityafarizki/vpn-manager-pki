package storage

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type CertAWSStorage struct {
	CAFileDir     string
	ClientCertDir string
	BucketName    string
	ca            *x509.Certificate
	caPrivKey     *rsa.PrivateKey
	cs            *CertFileStorage
	client        *s3.Client
}

func NewCertAWSStorage(caFileDir string, clientCertDir string, bucketName string) (*CertAWSStorage, error) {
	cs, err := NewCertFileStorage("/tmp/tmp_certs", "/tmp/tmp_client_certs")
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg)

	cas := &CertAWSStorage{
		CAFileDir:     caFileDir,
		ClientCertDir: clientCertDir,
		BucketName:    bucketName,
		cs:            cs,
		client:        client,
	}
	return cas, nil
}

// File naming structure would be {username}_cert.pem{|.revoked}
func (cas *CertAWSStorage) GetCertList() ([]*UserListEntry, error) {
	objList, err := cas.listFiles(cas.ClientCertDir)
	if err != nil {
		return nil, err
	}

	certList := []*UserListEntry{}
	certSuffix := "_cert.pem"
	revokedSuffix := ".revoked"

	suffixLength := len(certSuffix)
	prefixLength := len(cas.ClientCertDir + "/")
	revokedSuffixLength := len(revokedSuffix)

	for _, obj := range objList {
		keyLen := len(obj)
		if keyLen < prefixLength+suffixLength {
			continue
		}

		left := keyLen - suffixLength
		leftRevoked := keyLen - revokedSuffixLength
		right := keyLen

		if obj[left:right] == certSuffix {
			userEmail := obj[prefixLength:left]
			certList = append(certList, &UserListEntry{
				Email:     userEmail,
				IsRevoked: false,
			})
		} else if obj[leftRevoked:right] == revokedSuffix {
			userEmail := obj[prefixLength:(leftRevoked - prefixLength - 1)]
			certList = append(certList, &UserListEntry{
				Email:     userEmail,
				IsRevoked: true,
			})
		}
	}

	return certList, nil
}

func (cas *CertAWSStorage) SaveCRL(certs []pkix.RevokedCertificate) error {
	err := cas.cs.SaveCRL(certs)
	if err != nil {
		return err
	}
	crlObjectKey := cas.CAFileDir + "/crl.pem"
	tempFilePath := cas.cs.GetCACRLPath()

	err = cas.uploadFile(tempFilePath, crlObjectKey)

	return err
}

func (cas *CertAWSStorage) GetCRL() ([]pkix.RevokedCertificate, error) {
	crlObjectKey := cas.CAFileDir + "/crl.pem"
	tempFileDir := cas.cs.GetCACRLPath()

	err := cas.downloadFile(tempFileDir, crlObjectKey)
	if err != nil {
		return nil, err
	}

	return cas.cs.GetCRL()
}

func (cas *CertAWSStorage) SaveCert(privatekey *rsa.PrivateKey, cert *x509.Certificate) error {
	name := cert.Subject.CommonName
	err := cas.cs.SaveCert(privatekey, cert)
	if err != nil {
		return err
	}

	certPath, keyPath := cas.cs.GetClientCertPath(name)
	certObjectKey := fmt.Sprintf("%s/%s_cert.pem", cas.ClientCertDir, name)
	keyObjectKey := fmt.Sprintf("%s/%s_priv.pem", cas.ClientCertDir, name)

	err = cas.uploadFile(certPath, certObjectKey)
	if err != nil {
		return err
	}

	err = cas.uploadFile(keyPath, keyObjectKey)
	if err != nil {
		return err
	}

	return nil
}

func (cas *CertAWSStorage) SaveCA(privatekey *rsa.PrivateKey, cert *x509.Certificate) error {
	err := cas.cs.SaveCA(privatekey, cert)
	if err != nil {
		return err
	}

	caFilePath := cas.cs.GetCACertPath()
	caKeyPath := cas.cs.GetCAKeyPath()

	caObjectKey := fmt.Sprintf("%s/cert.pem", cas.CAFileDir)
	caKeyObjectKey := fmt.Sprintf("%s/priv.pem", cas.CAFileDir)

	err = cas.uploadFile(caFilePath, caObjectKey)
	if err != nil {
		return err
	}

	err = cas.uploadFile(caKeyPath, caKeyObjectKey)
	if err != nil {
		return err
	}

	return nil
}

func (cas *CertAWSStorage) GetCert(name string) (*rsa.PrivateKey, *x509.Certificate, bool, error) {
	certFilePath, keyFilePath := cas.cs.GetClientCertPath(name)
	certObjectKey := fmt.Sprintf("%s/%s_cert.pem", cas.ClientCertDir, name)
	keyObjectKey := fmt.Sprintf("%s/%s_priv.pem", cas.ClientCertDir, name)
	isRevoked := false

	err := cas.downloadFile(certFilePath, certObjectKey)
	if err != nil {
		if strings.Contains(err.Error(), "StatusCode: 404") {
			err := cas.downloadFile(certFilePath, certObjectKey+".revoked")
			if err != nil {
				return nil, nil, false, &fs.PathError{Path: certObjectKey, Op: "", Err: err}
			}
			isRevoked = true
		} else {
			return nil, nil, false, err
		}
	}

	err = cas.downloadFile(keyFilePath, keyObjectKey)
	if err != nil {
		if strings.Contains(err.Error(), "StatusCode: 404") {
			return nil, nil, false, &fs.PathError{Path: keyObjectKey, Op: "", Err: err}
		} else {
			return nil, nil, false, err
		}
	}

	privKey, cert, err := cas.cs.GetCert(name)
	return privKey, cert, isRevoked, err
}

func (cas *CertAWSStorage) GetCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	if cas.ca != nil && cas.caPrivKey != nil {
		return cas.caPrivKey, cas.ca, nil
	}

	caFilePath := cas.cs.GetCACertPath()
	caKeyPath := cas.cs.GetCAKeyPath()
	caObjectKey := fmt.Sprintf("%s/cert.pem", cas.CAFileDir)
	caKeyObjectKey := fmt.Sprintf("%s/priv.pem", cas.CAFileDir)

	err := cas.downloadFile(caFilePath, caObjectKey)
	if err != nil {
		return nil, nil, err
	}

	err = cas.downloadFile(caKeyPath, caKeyObjectKey)
	if err != nil {
		return nil, nil, err
	}

	caPrivKey, caCert, err := cas.cs.GetCA()
	if err != nil {
		return nil, nil, err
	}

	cas.ca = caCert
	cas.caPrivKey = caPrivKey

	return caPrivKey, caCert, err
}

func (cas *CertAWSStorage) MarkRevoked(cert *x509.Certificate) error {
	client, err := getAwsS3Client()
	if err != nil {
		return err
	}

	objectKey := fmt.Sprintf("%s/%s_cert.pem", cas.ClientCertDir, cert.Subject.CommonName)
	source := cas.BucketName + "/" + url.QueryEscape(objectKey)
	target := objectKey + ".revoked"

	_, err = client.CopyObject(context.TODO(), &s3.CopyObjectInput{
		Bucket:     &cas.BucketName,
		CopySource: &source,
		Key:        &target,
	})

	if err != nil {
		return err
	}

	client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: &cas.BucketName,
		Key:    &objectKey,
	})

	return nil
}

func (cas *CertAWSStorage) GetTlsCrypt() (string, error) {
	objectKey := cas.CAFileDir + "/tls_crypt.pem"
	filePath := cas.cs.CAFileDir + "/tls_crypt.pem"

	err := cas.downloadFile(filePath, objectKey)
	if err != nil {
		return "", err
	}

	return cas.cs.GetTlsCrypt()
}

func (cas *CertAWSStorage) GetVpnTemplate() (string, error) {
	objectKey := cas.CAFileDir + "/template.ovpn"
	filePath := cas.cs.CAFileDir + "/template.ovpn"

	err := cas.downloadFile(filePath, objectKey)
	if err != nil {
		return "", err
	}

	return cas.cs.GetVpnTemplate()
}

func (cas *CertAWSStorage) uploadFile(filePath string, fileKey string) error {
	uploader := manager.NewUploader(cas.client)
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = uploader.Upload(
		context.TODO(),
		&s3.PutObjectInput{Bucket: &cas.BucketName, Key: &fileKey, Body: file},
	)

	return err
}

func (cas *CertAWSStorage) downloadFile(filePath string, fileKey string) error {
	tempFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer tempFile.Close()

	downloader := manager.NewDownloader(cas.client)
	_, err = downloader.Download(
		context.TODO(),
		tempFile,
		&s3.GetObjectInput{Bucket: &cas.BucketName, Key: &fileKey},
	)
	return err
}

func (cas *CertAWSStorage) listFiles(path string) ([]string, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: &cas.BucketName,
		Prefix: &path,
	}

	resp, err := cas.client.ListObjectsV2(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	objKeyList := make([]string, len(resp.Contents))
	for i, obj := range resp.Contents {
		objKeyList[i] = *obj.Key
	}

	return objKeyList, nil
}

func getAwsS3Client() (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg)
	return client, nil
}
