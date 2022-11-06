package vpngatepki_test

import (
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"

	"github.com/adityafarizki/vpn-gate-pki/storage"
	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Get users list", Ordered, func() {
	var ginRouter *gin.Engine
	BeforeAll(func() {
		gin.DefaultWriter = io.Discard
		ginRouter = vpn.BuildGinRouter()
	})

	When("non Administrator user try to get user's list", func() {
		var response *httptest.ResponseRecorder
		BeforeAll(func() {
			user := generateRandomUser("", "")
			userJwt, err := buildUserJWT(user)
			Expect(err).To(BeNil())

			req, err := http.NewRequest("GET", "/users", nil)
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

	Context("Given there are user's entry", func() {
		var userCount int
		var usersList []*vpn.User
		var usersCert []*vpn.UserCert
		BeforeAll(func() {
			userCount = rand.Intn(20) + 5 // random number from 5 to 25
			usersList = make([]*vpn.User, userCount)
			usersCert = make([]*vpn.UserCert, userCount)

			for i := 0; i < userCount; i++ {
				usersList[i] = generateRandomUser("", "")
				userCert, err := vpn.CertMgr.CreateNewClientCert(usersList[i].Email)
				Expect(err).To(BeNil())
				usersCert[i] = userCert
				usersCert[i].IsRevoked = rand.Float32() <= 0.7

				if usersCert[i].IsRevoked {
					vpn.CertMgr.CertStorage.MarkRevoked(userCert.Cert)
				}
			}
		})

		AfterAll(func() {
			vpn.CertMgr.CertStorage.SaveCRL([]pkix.RevokedCertificate{})
			cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
		})

		When("Administrator user request user's list", func() {
			var response *httptest.ResponseRecorder
			BeforeAll(func() {
				admin := generateRandomUser("", "")
				userJwt, err := buildUserJWT(admin)
				Expect(err).To(BeNil())
				vpn.Config.AdminList = []string{admin.Email}

				req, err := http.NewRequest("GET", "/users", nil)
				Expect(err).To(BeNil())

				req.Header = map[string][]string{
					"Authorization": {"bearer " + userJwt},
				}
				response = httptest.NewRecorder()
				ginRouter.ServeHTTP(response, req)
			})

			AfterAll(func() {
				vpn.Config.AdminList = []string{}
			})

			It("Responds with status 200 OK", func() {
				Expect(response.Code).To(Equal(200))
			})

			It("Returns list of users", func() {
				responseBody, err := ioutil.ReadAll(response.Result().Body)
				Expect(err).To(BeNil())

				var fetchedList map[string][]storage.UserListEntry
				json.Unmarshal(responseBody, &fetchedList)
				sort.SliceStable(fetchedList["users"], func(i, j int) bool {
					return fetchedList["users"][i].Email < fetchedList["users"][j].Email
				})

				sort.SliceStable(usersCert, func(i, j int) bool {
					return usersCert[i].Cert.Subject.CommonName < usersCert[j].Cert.Subject.CommonName
				})

				Expect(len(fetchedList["users"])).To(Equal(len(usersCert)))

				for i := 0; i < len(usersCert); i++ {
					Expect(usersCert[i].Cert.Subject.CommonName).To(Equal(fetchedList["users"][i].Email))
					Expect(usersCert[i].IsRevoked).To(Equal(fetchedList["users"][i].IsRevoked))
				}
			})
		})
	})
})
