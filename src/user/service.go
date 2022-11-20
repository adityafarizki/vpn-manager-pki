package user

import (
	"crypto/x509"
	"errors"
	"fmt"
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
	usersCommonName, err := userService.CertManager.ListCertsCommonName()
	if err != nil {
		return nil, fmt.Errorf("getting user list error: %w", err)
	}

	revokedUsersList, err := userService.CertManager.GetRevokedList()
	if err != nil {
		return nil, fmt.Errorf("getting user list error: %w", err)
	}

	users := make([]*User, len(usersCommonName))
	for i, userName := range usersCommonName {
		isRevoked := false
		for _, revokedUser := range revokedUsersList {
			if userName == revokedUser {
				isRevoked = true
				break
			}
		}
		users[i] = &User{Email: userName, IsRevoked: isRevoked}
	}

	return users, nil
}

func (userService *UserService) RevokeUserCert(user *User) error {
	cert, _, err := userService.CertManager.GetCert(user.Email)
	if err != nil {
		if serr, ok := err.(NotFoundError); ok {
			errMessage := fmt.Sprintf("revoking user cert error not found: %s", serr.Error())
			return NotFoundError{Message: errMessage}
		} else {

		}
		return err
	}

	err = userService.CertManager.RevokeCert(cert)
	if err != nil {
		return fmt.Errorf("revoking user cert error: %w", err)
	}

	user.IsRevoked = true

	return nil
}

func (userService *UserService) GetUserCert(user *User) (*x509.Certificate, error) {
	cert, _, err := userService.CertManager.GetCert(user.Email)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (userService *UserService) GenerateUserCert(user *User) (*x509.Certificate, error) {
	cert, _, err := userService.CertManager.GetCert(user.Email)
	if _, isNotFound := err.(NotFoundError); err != nil && !isNotFound {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}

	isCertRevoked, err := userService.CertManager.IsCertRevoked(cert)
	if err != nil {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}
	if cert != nil && isCertRevoked {
		return nil, ForbiddenError{errors.New("User not allowed to generate cert when the previous one has been revoked")}
	}

	cert, _, err = userService.CertManager.GenerateCert(user.Email)
	if err != nil {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}

	return cert, nil
}