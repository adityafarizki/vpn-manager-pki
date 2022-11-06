package s3storage

import "github.com/aws/aws-sdk-go-v2/service/s3"

type S3Storage struct {
	BucketName string
	client     *s3.Client
}
