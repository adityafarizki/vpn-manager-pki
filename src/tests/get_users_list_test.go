package vpngatepki_test

import (
	"crypto/x509/pkix"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"

	"github.com/adityafarizki/vpn-gate-pki/config"
	"github.com/adityafarizki/vpn-gate-pki/user"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Get users list", Ordered, func() {
	When("non Administrator user try to get user's list", func() {
		var response *httptest.ResponseRecorder
		var testFixture *TestFixture
		BeforeAll(func() {
			var err error
			config, err := config.ConfigFromEnv()
			Expect(err).To(BeNil())

			testFixture, err = Bootstrap(config)
			Expect(err).To(BeNil())

			user := generateRandomUser("", "")
			userJwt, err := buildUserJWT(user, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
			Expect(err).To(BeNil())

			req, err := http.NewRequest("GET", "/users", nil)
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

	Context("Given there are user's entry", func() {
		var userCount int
		var usersList []*user.User
		var testFixture *TestFixture
		BeforeAll(func() {
			var err error
			config, err := config.ConfigFromEnv()
			Expect(err).To(BeNil())

			testFixture, err = Bootstrap(config)
			Expect(err).To(BeNil())

			userCount = rand.Intn(20) + 5 // random number from 5 to 25
			usersList = make([]*user.User, userCount)

			for i := 0; i < userCount; i++ {
				usersList[i] = generateRandomUser("", "")
				_, _, err := testFixture.CertManager.GenerateCert(usersList[i].Email)
				Expect(err).To(BeNil())
				isRevoked := rand.Float32() <= 0.7

				if isRevoked {
					testFixture.UserService.RevokeUserCert(usersList[i])
				}
			}
		})

		AfterAll(func() {
			testFixture.CertManager.SaveCrl(&pkix.CertificateList{})
			cleanS3BucketDir(testFixture.Storage.BucketName, "clients")
			cleanS3BucketDir(testFixture.Storage.BucketName, "revokedClients")
		})

		When("Administrator user request user's list", func() {
			var response *httptest.ResponseRecorder
			BeforeAll(func() {
				admin := generateRandomUser("", "")
				userJwt, err := buildUserJWT(admin, testFixture.KeyConfig.KeyId, testFixture.KeyConfig.PrivateKey)
				Expect(err).To(BeNil())

				testFixture.UserService.AdminList = []string{admin.Email}

				req, err := http.NewRequest("GET", "/users", nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Authorization": {"bearer " + userJwt},
				}
				response = httptest.NewRecorder()
				testFixture.Controller.Router.ServeHTTP(response, req)
			})

			AfterAll(func() {
				testFixture.UserService.AdminList = []string{}
			})

			It("Responds with status 200 OK", func() {
				Expect(response.Code).To(Equal(200))
			})

			It("Returns list of users", func() {
				responseBody, err := ioutil.ReadAll(response.Result().Body)
				Expect(err).To(BeNil())

				var fetchedList map[string][]*user.User
				json.Unmarshal(responseBody, &fetchedList)
				sort.SliceStable(fetchedList["users"], func(i, j int) bool {
					return fetchedList["users"][i].Email < fetchedList["users"][j].Email
				})

				sort.SliceStable(usersList, func(i, j int) bool {
					return usersList[i].Email < usersList[j].Email
				})

				Expect(len(fetchedList["users"])).To(Equal(len(usersList)))
				for i := 0; i < len(usersList); i++ {
					Expect(usersList[i].Email).To(Equal(fetchedList["users"][i].Email))
					Expect(usersList[i].IsRevoked).To(Equal(fetchedList["users"][i].IsRevoked))
				}
			})
		})
	})
})
