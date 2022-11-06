package vpngatepki_test

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
)

var _ = Describe("Get user's vpn config", Ordered, func() {
	var ginRouter *gin.Engine
	BeforeAll(func() {
		gin.DefaultWriter = io.Discard
		ginRouter = vpn.BuildGinRouter()
	})

	Describe("Given user doesn't exist before", func() {
		BeforeAll(func() {
			cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
		})

		Context("When client send request to create vpn user", func() {
			var response *httptest.ResponseRecorder
			var user *vpn.User
			BeforeAll(func() {
				user = generateRandomUser("", "")
				userJwt, err := buildUserJWT(user)
				Expect(err).To(BeNil())

				req, err := http.NewRequest("GET", "/vpn-config", nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Authorization": {"bearer " + userJwt},
				}
				response = httptest.NewRecorder()
				ginRouter.ServeHTTP(response, req)
			})

			It("Responds with 200 OK", func() {
				Expect(response.Code).To(Equal(200))
			})

			It("Creates user cert in storage backend", func() {
				s3Client, err := getAwsS3Client()
				Expect(err).To(BeNil())

				objects, err := listBucketObjects(s3Client, vpn.Config.S3BucketName, "client")
				Expect(err).To(BeNil())
				Expect(len(objects)).To(Equal(2))
			})

			It("Returns user vpn config with cert that is signed by CA", func() {
				responseBody, err := io.ReadAll(response.Body)
				Expect(err).To(BeNil())

				var responseJson map[string]string
				err = json.Unmarshal(responseBody, &responseJson)
				Expect(err).To(BeNil())

				cert, err := getCertFromVPNConfig(responseJson["config"])
				Expect(err).To(BeNil())

				_, ca, err := vpn.CertMgr.GetCA()
				Expect(err).To(BeNil())

				roots := x509.NewCertPool()
				roots.AddCert(ca)
				_, err = cert.Verify(x509.VerifyOptions{
					Roots: roots,
				})
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("Given user already exists before", func() {
		var user *vpn.User
		var userVpnConfig string
		BeforeAll(func() {
			cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
			user = generateRandomUser("", "")

			var err error
			userVpnConfig, err = vpn.GetUserVPNConfig(user)
			Expect(err).To(BeNil())
		})

		AfterAll(func() {
			cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
		})

		Context("When client send request to create vpn user", func() {
			var response *httptest.ResponseRecorder
			BeforeAll(func() {
				userJwt, err := buildUserJWT(user)
				Expect(err).To(BeNil())

				req, err := http.NewRequest("GET", "/vpn-config", nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Authorization": {"bearer " + userJwt},
				}
				response = httptest.NewRecorder()
				ginRouter.ServeHTTP(response, req)
			})

			It("Responds with 200 OK", func() {
				Expect(response.Code).To(Equal(200))
			})

			It("Returns user vpn config", func() {
				responseBody, err := io.ReadAll(response.Body)
				Expect(err).To(BeNil())

				var responseJson map[string]string
				err = json.Unmarshal(responseBody, &responseJson)
				Expect(err).To(BeNil())

				Expect(responseJson["config"]).To(Equal(userVpnConfig))
			})
		})
	})
})
