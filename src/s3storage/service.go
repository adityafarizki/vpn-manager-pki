package s3storage

// Implements IStorage from "github.com/adityafarizki/vpn-gate-pki/certmanager"
import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func NewS3Storage(bucketName string) (*S3Storage, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg)

	return &S3Storage{
		client:     client,
		BucketName: bucketName,
	}, err
}

func (storage *S3Storage) GetFile(path string) ([]byte, error) {
	response, err := storage.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &storage.BucketName,
		Key:    &path,
	})
	if err != nil {
		return nil, fmt.Errorf("s3 GetFile error: %w", err)
	}

	file, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 GetFile error: %w", err)
	}

	return file, nil
}

func (storage *S3Storage) SaveFile(path string, data []byte) error {
	dataReader := bytes.NewReader(data)
	_, err := storage.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &storage.BucketName,
		Key:    &path,
		Body:   dataReader,
	})
	if err != nil {
		return fmt.Errorf("s3 SaveFile error: %w", err)
	}

	return nil
}

func (storage *S3Storage) ListDir(path string) ([]string, error) {
	response, err := storage.client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: &storage.BucketName,
		Prefix: &path,
	})
	if err != nil {
		return nil, fmt.Errorf("s3 ListDir error: %w", err)
	}

	result := make([]string, len(response.Contents))
	for i, object := range response.Contents {
		result[i] = *object.Key
	}

	return result, nil
}
