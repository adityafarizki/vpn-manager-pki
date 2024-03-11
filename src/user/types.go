package user

type User struct {
	Email     string
	IsRevoked bool
}

type UserService struct {
	CertManager     IUserCertManager
	DataStorage     IUserDataStorage
	UserDataDirPath string
	AdminList       []string
}
