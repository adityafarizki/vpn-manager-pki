package user

type User struct {
	Email string
}

type UserService struct {
	certManager IUserCertManager
	adminList   []string
}
