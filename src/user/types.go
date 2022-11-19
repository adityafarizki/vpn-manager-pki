package user

type User struct {
	Email     string
	IsRevoked bool
}

type UserService struct {
	CertManager IUserCertManager
	AdminList   []string
}
