package user

type User struct {
	Email string
}

type UserService struct {
	CertManager IUserCertManager
	AdminList   []string
}
