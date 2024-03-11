package user

import (
	"crypto/x509"
	"fmt"

	cmerr "github.com/adityafarizki/vpn-gate-pki/commonerrors"
)

func UserFromCert(cert *x509.Certificate) (*User, error) {
	return &User{Email: cert.Subject.CommonName}, nil
}

func (userService *UserService) IsUserAdmin(user *User) bool {
	for _, admin := range userService.AdminList {
		if user.Email == admin {
			return true
		}
	}

	return false
}

func (userService *UserService) GetUsersList() ([]*User, error) {
	usersName, err := userService.DataStorage.ListDir(userService.UserDataDirPath)
	if err != nil {
		return nil, fmt.Errorf("getting user list error: %w", err)
	}

	users := make([]*User, len(usersName))
	for i, userName := range usersName {
		revokedIndicatorLen := len("_revoked")
		isUserRevoked := len(userName) > revokedIndicatorLen && userName[len(userName)-revokedIndicatorLen:] == "_revoked"
		if isUserRevoked {
			users[i] = &User{Email: userName[:len(userName)-revokedIndicatorLen], IsRevoked: true}
		} else {
			users[i] = &User{Email: userName, IsRevoked: false}
		}
	}

	return users, nil
}

func (userService *UserService) RevokeUserAccess(user *User) error {
	cert, _, err := userService.CertManager.GetCert(user.Email)
	if err != nil {
		if serr, ok := err.(cmerr.NotFoundError); ok {
			errMessage := fmt.Sprintf("revoking user cert error not found: %s", serr.Error())
			return cmerr.NotFoundError{Message: errMessage}
		} else {
			return err
		}
	}

	err = userService.CertManager.RevokeCert(cert)
	if err != nil {
		return fmt.Errorf("revoking user cert error: %w", err)
	}

	user.IsRevoked = true

	return nil
}

func (userService *UserService) RegisterUser(email string) (*User, *x509.Certificate, error) {
	user, err := userService.DataStorage.GetFile(userService.UserDataDirPath + "/" + email)
	if err != nil {
		return nil, fmt.Errorf("getting user list error: %w", err)
	}
}

func (userService *UserService) GetUserCert(user *User) (*x509.Certificate, error) {
	cert, _, err := userService.CertManager.GetCert(user.Email)
	if err != nil {
		if serr, ok := err.(cmerr.NotFoundError); ok {
			errMessage := fmt.Sprintf("get user cert error not found: %s", serr.Error())
			return nil, cmerr.NotFoundError{Message: errMessage}
		} else {
			return nil, err
		}
	}

	return cert, nil
}

func (userService *UserService) GenerateUserCert(user *User) (*x509.Certificate, error) {
	cert, _, err := userService.CertManager.GetCert(user.Email)
	if _, isNotFound := err.(cmerr.NotFoundError); err != nil && !isNotFound {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}

	isCertRevoked, err := userService.CertManager.IsCertRevoked(cert)
	if err != nil {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}
	if cert != nil && isCertRevoked {
		return nil, cmerr.ForbiddenError{Message: "User not allowed to generate cert when the previous one has been revoked"}
	}

	cert, _, err = userService.CertManager.GenerateCert(user.Email)
	if err != nil {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}

	return cert, nil
}
