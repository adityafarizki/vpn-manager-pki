package vpngatepki_test

// import (
// 	"crypto/x509/pkix"
// 	"io"
// 	"net/http"
// 	"net/http/httptest"
// 	"time"

// 	"github.com/gin-gonic/gin"
// 	. "github.com/onsi/ginkgo/v2"
// 	. "github.com/onsi/gomega"

// 	vpn "github.com/adityafarizki/vpn-gate-pki/vpngatepki"
// )

// var _ = Describe("revoke user cert", Ordered, func() {
// 	var ginRouter *gin.Engine
// 	BeforeAll(func() {
// 		gin.DefaultWriter = io.Discard
// 		ginRouter = vpn.BuildGinRouter()
// 	})

// 	Context("Given requester is not admin", func() {
// 		var user *vpn.User
// 		BeforeAll(func() {
// 			user = generateRandomUser("", "")
// 			vpn.Config.AdminList = []string{}
// 		})

// 		When("The requester request to revoke a user cert", func() {
// 			var response *httptest.ResponseRecorder
// 			BeforeAll(func() {
// 				userJwt, err := buildUserJWT(user)
// 				Expect(err).To(BeNil())

// 				req, err := http.NewRequest("DELETE", "/user/"+user.Email, nil)
// 				Expect(err).To(BeNil())

// 				req.Header = map[string][]string{
// 					"Authorization": {"bearer " + userJwt},
// 				}
// 				response = httptest.NewRecorder()
// 				ginRouter.ServeHTTP(response, req)
// 			})

// 			It("Responds with status 403 Unauthorized", func() {
// 				Expect(response.Code).To(Equal(403))
// 			})
// 		})
// 	})

// 	Context("Given requester is admin", func() {
// 		var requester *vpn.User
// 		BeforeAll(func() {
// 			requester = generateRandomUser("", "")
// 			vpn.Config.AdminList = []string{requester.Email}
// 		})

// 		AfterAll(func() {
// 			cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
// 			vpn.Config.AdminList = []string{}
// 		})

// 		Describe("Given user cert doesn't exists", func() {
// 			When("requester send request to revoke user cert", func() {
// 				var response *httptest.ResponseRecorder
// 				var user *vpn.User
// 				BeforeAll(func() {
// 					user = generateRandomUser("", "")
// 					requesterJwt, err := buildUserJWT(requester)
// 					Expect(err).To(BeNil())

// 					req, err := http.NewRequest("DELETE", "/user/"+user.Email, nil)
// 					Expect(err).To(BeNil())

// 					req.Header = map[string][]string{
// 						"Authorization": {"bearer " + requesterJwt},
// 					}
// 					response = httptest.NewRecorder()
// 					ginRouter.ServeHTTP(response, req)
// 				})

// 				It("Responds with 404 Not Found", func() {
// 					Expect(response.Code).To(Equal(404))
// 				})
// 			})
// 		})

// 		Describe("Given user cert exists", func() {
// 			var user *vpn.User
// 			var userCert *vpn.UserCert
// 			BeforeAll(func() {
// 				user = generateRandomUser("", "")

// 				var err error
// 				userCert, err = vpn.CertMgr.CreateNewClientCert(user.Email)
// 				Expect(err).To(BeNil())

// 				vpn.Config.AdminList = []string{user.Email}
// 			})

// 			AfterAll(func() {
// 				vpn.Config.AdminList = []string{}
// 				cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
// 			})

// 			Describe("Given user cert has been revoked", func() {
// 				BeforeAll(func() {
// 					vpn.CertMgr.CertStorage.SaveCRL([]pkix.RevokedCertificate{
// 						{
// 							SerialNumber:   userCert.Cert.SerialNumber,
// 							RevocationTime: time.Now(),
// 						},
// 					})
// 					vpn.CertMgr.CertStorage.MarkRevoked(userCert.Cert)
// 				})

// 				AfterAll(func() {
// 					vpn.CertMgr.CertStorage.SaveCRL([]pkix.RevokedCertificate{})
// 					cleanS3BucketDir(vpn.Config.S3BucketName, "clients")

// 					var err error
// 					userCert, err = vpn.CertMgr.CreateNewClientCert(user.Email)
// 					Expect(err).To(BeNil())
// 				})

// 				When("Client send request to revoke user's cert", func() {
// 					var response *httptest.ResponseRecorder
// 					BeforeAll(func() {
// 						userJwt, err := buildUserJWT(user)
// 						Expect(err).To(BeNil())

// 						req, err := http.NewRequest("DELETE", "/user/"+user.Email, nil)
// 						Expect(err).To(BeNil())

// 						req.Header = map[string][]string{
// 							"Authorization": {"bearer " + userJwt},
// 						}
// 						response = httptest.NewRecorder()
// 						ginRouter.ServeHTTP(response, req)
// 					})

// 					It("Responds with status 200 OK", func() {
// 						Expect(response.Code).To(Equal(200))
// 					})

// 					It("Keeps the same CRL", func() {
// 						crl, err := vpn.CertMgr.CertStorage.GetCRL()
// 						Expect(err).To(BeNil())
// 						Expect(len(crl)).To(Equal(1))

// 						crlGob, err := crl[0].SerialNumber.GobEncode()
// 						Expect(err).To(BeNil())

// 						userGob, err := userCert.Cert.SerialNumber.GobEncode()
// 						Expect(err).To(BeNil())

// 						Expect(crlGob).To(Equal(userGob))
// 					})
// 				})
// 			})

// 			Describe("Given user cert hasn't been revoked", func() {
// 				When("Client send request to revoke user's cert", func() {
// 					var response *httptest.ResponseRecorder
// 					BeforeAll(func() {
// 						userJwt, err := buildUserJWT(user)
// 						Expect(err).To(BeNil())

// 						req, err := http.NewRequest("DELETE", "/user/"+user.Email, nil)
// 						Expect(err).To(BeNil())

// 						req.Header = map[string][]string{
// 							"Authorization": {"bearer " + userJwt},
// 						}
// 						response = httptest.NewRecorder()
// 						ginRouter.ServeHTTP(response, req)
// 					})

// 					AfterAll(func() {
// 						vpn.CertMgr.CertStorage.SaveCRL([]pkix.RevokedCertificate{})
// 						cleanS3BucketDir(vpn.Config.S3BucketName, "clients")

// 						var err error
// 						userCert, err = vpn.CertMgr.CreateNewClientCert(user.Email)
// 						Expect(err).To(BeNil())
// 					})

// 					It("Responds with status 200 OK", func() {
// 						Expect(response.Code).To(Equal(200))
// 					})

// 					It("Adds user cert to CRL", func() {
// 						crl, err := vpn.CertMgr.CertStorage.GetCRL()
// 						Expect(err).To(BeNil())
// 						Expect(len(crl)).To(Equal(1))

// 						crlGob, err := crl[0].SerialNumber.GobEncode()
// 						Expect(err).To(BeNil())

// 						userGob, err := userCert.Cert.SerialNumber.GobEncode()
// 						Expect(err).To(BeNil())

// 						Expect(crlGob).To(Equal(userGob))
// 					})

// 					It("Mark user's cert as being revoked", func() {
// 						cert, err := vpn.CertMgr.GetClientCert(user.Email)
// 						Expect(err).To(BeNil())
// 						Expect(cert.IsRevoked).To(BeTrue())
// 					})
// 				})
// 			})
// 		})
// 	})
// })
