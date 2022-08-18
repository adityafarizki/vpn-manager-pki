package vpngatepki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
)

var _ = Describe("revoke user cert", Ordered, func() {
	var ginRouter *gin.Engine
	BeforeAll(func() {
		gin.DefaultWriter = io.Discard
		ginRouter = vpn.BuildGinRouter()
	})

	Describe("Given requester is not admin", func() {
		var user *vpn.User
		BeforeAll(func() {
			user = generateRandomUser("", "")
			vpn.Config.AdminList = []string{}
		})

		Describe("When the requester request to revoke a user cert", func() {
			var response *httptest.ResponseRecorder
			BeforeAll(func() {
				userJwt, err := buildUserJWT(user)
				Expect(err).To(BeNil())

				req, err := http.NewRequest("DELETE", "/user/"+user.Email, nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Authorization": {"bearer " + userJwt},
				}
				response = httptest.NewRecorder()
				ginRouter.ServeHTTP(response, req)
			})

			It("Responds with status 403 Unauthorized", func() {
				Expect(response.Code).To(Equal(403))
			})
		})
	})

	Describe("Given requester is admin", func() {
		var requester *vpn.User
		BeforeAll(func() {
			requester = generateRandomUser("", "")
			vpn.Config.AdminList = []string{requester.Email}
		})

		AfterAll(func() {
			cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
			vpn.Config.AdminList = []string{}
		})

		Describe("Given user cert doesn't exists", func() {
			Context("When requester send request to revoke user cert", func() {
				var response *httptest.ResponseRecorder
				var user *vpn.User
				BeforeAll(func() {
					user = generateRandomUser("", "")
					requesterJwt, err := buildUserJWT(requester)
					Expect(err).To(BeNil())

					req, err := http.NewRequest("DELETE", "/user/"+user.Email, nil)
					Expect(err).To(BeNil())

					req.Header = map[string][]string{
						"Authorization": {"bearer " + requesterJwt},
					}
					response = httptest.NewRecorder()
					ginRouter.ServeHTTP(response, req)
				})

				It("Responds with 404 Not Found", func() {
					Expect(response.Code).To(Equal(404))
				})
			})
		})

		Describe("Given user cert exists", func() {
			var user *vpn.User
			var userCert *x509.Certificate
			BeforeAll(func() {
				user = generateRandomUser("", "")

				var err error
				userCert, err = vpn.CertMgr.CreateNewClientCert(user.Email)
				Expect(err).To(BeNil())

				vpn.Config.AdminList = []string{user.Email}
			})

			AfterAll(func() {
				vpn.Config.AdminList = []string{}
				cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
			})

			Describe("Given user cert hasn't been revoked", func() {
				When("Client send request to revoke user's cert", func() {
					var response *httptest.ResponseRecorder
					BeforeAll(func() {
						userJwt, err := buildUserJWT(user)
						Expect(err).To(BeNil())

						req, err := http.NewRequest("DELETE", "/user/"+user.Email, nil)
						Expect(err).To(BeNil())

						req.Header = map[string][]string{
							"Authorization": {"bearer " + userJwt},
						}
						response = httptest.NewRecorder()
						ginRouter.ServeHTTP(response, req)
					})

					AfterAll(func() {
						vpn.CertMgr.CertStorage.SaveCRL([]pkix.RevokedCertificate{})
					})

					It("Responds with status 200 OK", func() {
						fmt.Println(response.Body)
						Expect(response.Code).To(Equal(200))
					})

					It("Adds user cert to CRL", func() {
						crl, err := vpn.CertMgr.CertStorage.GetCRL()
						Expect(err).To(BeNil())
						Expect(len(crl)).To(Equal(1))

						crlGob, err := crl[0].SerialNumber.GobEncode()
						Expect(err).To(BeNil())

						userGob, err := userCert.SerialNumber.GobEncode()
						Expect(err).To(BeNil())

						Expect(crlGob).To(Equal(userGob))
					})

					It("Appends '.revoked' to user's cert file", func() {
						client, err := getAwsS3Client()
						Expect(err).To(BeNil())

						clientPath := fmt.Sprintf("clients/%s_cert.pem.revoked", user.Email)
						_, err = getObject(client, vpn.Config.S3BucketName, clientPath)
						Expect(err).To(BeNil())
					})
				})
			})
		})
	})
})
