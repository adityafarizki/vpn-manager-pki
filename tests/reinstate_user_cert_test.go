package vpngatepki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/adityafarizki/vpn-gate-pki/pkg/config"
	"github.com/adityafarizki/vpn-gate-pki/pkg/user"
)

var _ = Describe("reinstate user cert", Ordered, func() {
	var testFixture *TestFixture
	BeforeAll(func() {
		var err error
		config, err := config.ConfigFromEnv()
		Expect(err).To(BeNil())

		testFixture, err = Bootstrap(config)
		Expect(err).To(BeNil())
	})

	Context("Given requester is not admin", func() {
		var user *user.User
		BeforeAll(func() {
			user = generateRandomUser("", "")
			testFixture.UserService.AdminList = []string{}
		})

		When("The requester request to reinstate a user cert", func() {
			var response *httptest.ResponseRecorder
			BeforeAll(func() {
				userJwt, err := buildUserJWT(user, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
				Expect(err).To(BeNil())

				req, err := http.NewRequest("PUT", "/api/user/"+user.Email+"/reinstate", nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Authorization": {"bearer " + userJwt},
				}
				response = httptest.NewRecorder()
				testFixture.Controller.Router.ServeHTTP(response, req)
			})

			It("Responds with status 403 Unauthorized", func() {
				Expect(response.Code).To(Equal(403))
			})
		})
	})

	Context("Given requester is admin", func() {
		var requester *user.User
		BeforeAll(func() {
			requester = generateRandomUser("", "")
			testFixture.UserService.AdminList = []string{requester.Email}
		})

		AfterAll(func() {
			cleanS3BucketDir(testFixture.Storage.BucketName, "clients")
			cleanS3BucketDir(testFixture.Storage.BucketName, "users")
			testFixture.UserService.AdminList = []string{}
		})

		Describe("Given user doesn't exists", func() {
			When("requester send request to reinstate user cert", func() {
				var response *httptest.ResponseRecorder
				var user *user.User
				BeforeAll(func() {
					user = generateRandomUser("", "")
					requesterJwt, err := buildUserJWT(requester, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
					Expect(err).To(BeNil())

					req, err := http.NewRequest("PUT", "/api/user/"+user.Email+"/reinstate", nil)
					Expect(err).To(BeNil())

					req.Header = map[string][]string{
						"Authorization": {"bearer " + requesterJwt},
					}
					response = httptest.NewRecorder()
					testFixture.Controller.Router.ServeHTTP(response, req)
				})

				It("Responds with 404 Not Found", func() {
					Expect(response.Code).To(Equal(404))
				})
			})
		})

		Describe("Given user exists", func() {
			var user *user.User
			var userCert *x509.Certificate
			BeforeAll(func() {
				user = generateRandomUser("", "")

				var err error
				_, userCert, err = testFixture.UserService.RegisterUser(user.Email)
				Expect(err).To(BeNil())

				testFixture.UserService.AdminList = []string{user.Email}
			})

			AfterAll(func() {
				testFixture.UserService.AdminList = []string{}
				cleanS3BucketDir(testFixture.Storage.BucketName, "clients")
				cleanS3BucketDir(testFixture.Storage.BucketName, "users")

			})

			Describe("Given user cert has been revoked", func() {
				BeforeAll(func() {
					testFixture.UserService.RevokeUserAccess(user)
				})

				AfterAll(func() {
					testFixture.CertManager.SaveCrl(&pkix.CertificateList{})

				})

				When("Client send request to reinstate user's cert", func() {
					var response *httptest.ResponseRecorder
					BeforeAll(func() {
						userJwt, err := buildUserJWT(user, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
						Expect(err).To(BeNil())

						req, err := http.NewRequest("PUT", "/api/user/"+user.Email+"/reinstate", nil)
						Expect(err).To(BeNil())

						req.Header = map[string][]string{
							"Authorization": {"bearer " + userJwt},
						}
						response = httptest.NewRecorder()
						testFixture.Controller.Router.ServeHTTP(response, req)
					})

					It("Responds with status 200 OK", func() {
						Expect(response.Code).To(Equal(200))
					})

					It("Generates new cert for the user", func() {
						crl, err := testFixture.CertManager.GetCrl()
						Expect(err).To(BeNil())

						revokedCerts := crl.TBSCertList.RevokedCertificates
						Expect(len(revokedCerts)).To(Equal(1))

						crlGob, err := revokedCerts[0].SerialNumber.GobEncode()
						Expect(err).To(BeNil())

						userCert, _, err = testFixture.CertManager.GetCert(user.Email)
						Expect(err).To(BeNil())

						userGob, err := userCert.SerialNumber.GobEncode()
						Expect(err).To(BeNil())

						Expect(crlGob).To(Not(Equal(userGob)))
					})
				})
			})

			Describe("Given user cert hasn't been revoked", func() {
				When("Client send request to reinstate user's cert", func() {
					var response *httptest.ResponseRecorder
					BeforeAll(func() {
						userJwt, err := buildUserJWT(user, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
						Expect(err).To(BeNil())

						req, err := http.NewRequest("DELETE", "/api/user/"+user.Email, nil)
						Expect(err).To(BeNil())

						req.Header = map[string][]string{
							"Authorization": {"bearer " + userJwt},
						}

						response = httptest.NewRecorder()
						testFixture.Controller.Router.ServeHTTP(response, req)
					})

					AfterAll(func() {
						testFixture.CertManager.SaveCrl(&pkix.CertificateList{})

						testFixture.UserService.RegisterUser(user.Email)
					})

					It("Responds with status 200 OK", func() {
						Expect(response.Code).To(Equal(200))
					})

					It("Does nothing", func() {
						crl, err := testFixture.CertManager.GetCrl()
						Expect(err).To(BeNil())

						revokedCerts := crl.TBSCertList.RevokedCertificates
						Expect(len(revokedCerts)).To(Equal(1))

						currentCert, _, err := testFixture.CertManager.GetCert(user.Email)
						Expect(err).To(BeNil())

						Expect(currentCert.SerialNumber).To(Equal(userCert.SerialNumber))
					})
				})
			})
		})
	})
})
