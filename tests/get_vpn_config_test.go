package vpngatepki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/adityafarizki/vpn-gate-pki/pkg/config"
	"github.com/adityafarizki/vpn-gate-pki/pkg/user"
)

var _ = Describe("Get user's vpn config", Ordered, func() {
	var response *httptest.ResponseRecorder
	var testFixture *TestFixture
	BeforeAll(func() {
		var err error
		config, err := config.ConfigFromEnv()
		Expect(err).To(BeNil())

		testFixture, err = Bootstrap(config)
		Expect(err).To(BeNil())
		cleanS3BucketDir(testFixture.Storage.BucketName, "clients")
		cleanS3BucketDir(testFixture.Storage.BucketName, "users")
	})

	Describe("Given user doesn't exist before", func() {
		Context("When client send request to create vpn user", func() {
			var user *user.User
			BeforeAll(func() {
				user = generateRandomUser("", "")
				userJwt, err := buildUserJWT(user, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
				Expect(err).To(BeNil())

				req, err := http.NewRequest("GET", "/vpn-config", nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Cookie": {"authJwt=" + userJwt},
				}
				response = httptest.NewRecorder()
				testFixture.Controller.Router.ServeHTTP(response, req)
			})

			AfterAll(func() {
				testFixture.CertManager.SaveCrl(&pkix.CertificateList{})
				cleanS3BucketDir(testFixture.Storage.BucketName, "clients")
				cleanS3BucketDir(testFixture.Storage.BucketName, "users")
			})

			It("Responds with 200 OK", func() {
				Expect(response.Code).To(Equal(200))
			})

			It("Creates user cert", func() {
				cert, err := testFixture.UserService.GetUserCert(user)
				Expect(err).To(BeNil())
				Expect(cert.Subject.CommonName).To(Equal(user.Email))
			})

			It("Returns user vpn config with cert that is signed by CA", func() {
				responseBody, err := io.ReadAll(response.Body)
				Expect(err).To(BeNil())

				vpnConfigs, err := unzip(responseBody)
				Expect(err).To(BeNil())
				for _, config := range vpnConfigs {
					cert, err := getCertFromVPNConfig(string(config))
					Expect(err).To(BeNil())

					ca, _, err := testFixture.CertManager.GetRootCert()
					Expect(err).To(BeNil())

					roots := x509.NewCertPool()
					roots.AddCert(ca)
					_, err = cert.Verify(x509.VerifyOptions{
						Roots: roots,
					})
					Expect(err).To(BeNil())
				}
			})
		})
	})

	Describe("Given user already exists before", func() {
		var user *user.User
		var userVpnConfig map[string]string
		BeforeAll(func() {
			cleanS3BucketDir(testFixture.Storage.BucketName, "clients")
			cleanS3BucketDir(testFixture.Storage.BucketName, "users")
			user = generateRandomUser("", "")

			var err error
			testFixture.UserService.RegisterUser(user.Email)
			userVpnConfig, err = testFixture.VpnManager.GetUserConfig(user)
			Expect(err).To(BeNil())
		})

		AfterAll(func() {
			cleanS3BucketDir(testFixture.Storage.BucketName, "clients")
			cleanS3BucketDir(testFixture.Storage.BucketName, "users")
		})

		Context("When client send request to create vpn user", func() {
			var response *httptest.ResponseRecorder
			BeforeAll(func() {
				userJwt, err := buildUserJWT(user, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
				Expect(err).To(BeNil())

				req, err := http.NewRequest("GET", "/vpn-config", nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Cookie": {"authJwt=" + userJwt},
				}
				response = httptest.NewRecorder()
				testFixture.Controller.Router.ServeHTTP(response, req)
			})

			It("Responds with 200 OK", func() {
				Expect(response.Code).To(Equal(200))
			})

			It("Returns user vpn config", func() {
				responseBody, err := io.ReadAll(response.Body)
				Expect(err).To(BeNil())

				vpnConfigs, err := unzip(responseBody)
				Expect(err).To(BeNil())

				for name, config := range vpnConfigs {
					conf := string(config)
					userConf := userVpnConfig[name[:len(name)-5]] // cut the .ovpn

					Expect(conf).To(Equal(userConf))
				}
			})
		})
	})
})
