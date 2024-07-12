package certmanager

type CertManager struct {
	CaDirPath       string
	UserCertDirPath string
	CertStorage     IStorage
}
