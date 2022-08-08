package vpngatepki_test

import (
	"context"
	"math/rand"
	"time"

	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func cleanS3BucketDir(bucket string, dir string) error {
	client, err := getAwsS3Client()
	if err != nil {
		return err
	}

	objects, err := listBucketObjects(client, bucket, dir)
	if err != nil {
		return err
	}

	err = deleteObjects(client, bucket, objects)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return nil
}

func getAwsS3Client() (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg)
	return client, nil
}

func listBucketObjects(client *s3.Client, bucket string, dir string) ([]string, error) {
	var result []string
	continueLoop := true
	var nextToken *string = nil

	for continueLoop {
		response, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &dir,
			ContinuationToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, obj := range response.Contents {
			result = append(result, *obj.Key)
		}

		nextToken = response.NextContinuationToken
		continueLoop = nextToken != nil
	}

	return result, nil
}

func deleteObjects(client *s3.Client, bucket string, keys []string) error {
	objectIdList := make([]types.ObjectIdentifier, len(keys))
	for i := range keys {
		objectIdList[i].Key = &keys[i]
	}

	input := &s3.DeleteObjectsInput{
		Bucket: &bucket,
		Delete: &types.Delete{Objects: objectIdList},
	}

	_, err := client.DeleteObjects(context.TODO(), input)
	if err != nil {
		return err
	}

	return nil
}

func randomString(length int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const letterLen = len(letterBytes)
	result := make([]byte, length)

	for i := range result {
		result[i] = letterBytes[rand.Intn(letterLen)]
	}
	return string(result)
}

func generateRandomUser(email string, sub string) *vpn.User {
	if email == "" {
		email = randomString(10) + "@" + randomString(8) + ".com"
	}

	if sub == "" {
		sub = uuid.NewString()
	}

	return &vpn.User{
		Email: email,
		Sub:   sub,
	}
}

func buildUserJWT(user *vpn.User) (string, error) {
	var result string

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            "https://accounts.google.com",
		"azp":            randomString(40),
		"aud":            randomString(40),
		"sub":            user.Sub,
		"email":          user.Email,
		"email_verified": true,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Unix() + 3600,
	})
	token.Header = map[string]interface{}{
		"kid": jwtKeyId,
		"typ": "JWT",
		"alg": "RS256",
	}
	result, err := token.SignedString(jwtPrivKey)
	if err != nil {
		return "", err
	}

	return result, nil
}
