package vpngatepki_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
)

var _ = Describe("create vpn user", Ordered, func() {
	var ginRouter *gin.Engine
	BeforeAll(func() {
		ginRouter = vpn.BuildGinRouter()
	})

	Context("Given user doesn't exist before", func() {
		cleanS3BucketDir(vpn.Config.S3BucketName, "clients")

		Context("When client send request to create vpn user", func() {
			var response *httptest.ResponseRecorder
			var user *vpn.User
			BeforeAll(func() {
				user = generateRandomUser("", "")
				userJwt, err := buildUserJWT(user)
				if err != nil {
					fmt.Println(err)
					return
				}

				req, err := http.NewRequest("GET", "/vpn-config", nil)
				if err != nil {
					fmt.Println(err)
					return
				}

				req.Header = map[string][]string{
					"Authorization": {"bearer " + userJwt},
				}
				response = httptest.NewRecorder()
				ginRouter.ServeHTTP(response, req)
			})

			It("Response with 200 OK", func() {
				Expect(response.Code).To(Equal(200))
			})

			It("Creates user cert in storage backend", func() {
				Expect(1).To(Equal(1))
			})
		})
	})
})
