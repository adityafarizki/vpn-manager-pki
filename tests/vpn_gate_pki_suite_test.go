package vpngatepki_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vpn "github.com/adityafarizki/vpn-gate-pki"
)

func TestVpnGatePki(t *testing.T) {
	vpn.Bootstrap()
	vpn.InitPKI()
	RegisterFailHandler(Fail)
	RunSpecs(t, "VpnGatePki Suite")
	cleanS3BucketDir(vpn.Config.S3BucketName, "clients")
}

var _ = Describe("vpn-gate-pki", func() {
	It("test", func() {
		Expect(1).To(Equal(2))
	})
})
