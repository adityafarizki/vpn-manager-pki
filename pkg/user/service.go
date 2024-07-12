package user

import (
	"crypto/x509"
	"fmt"

	cmerr "github.com/adityafarizki/vpn-gate-pki/pkg/commonerrors"
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
	cert, err := userService.GetUserCert(user)
	if err != nil {
		if serr, ok := err.(cmerr.NotFoundError); ok {
			errMessage := fmt.Sprintf("revoking user cert error not found: %s", serr.Error())
			return cmerr.NotFoundError{Message: errMessage}
		} else {
			return err
		}
	}

	isCertRevoked, err := userService.CertManager.IsCertRevoked(cert)
	if err != nil {
		return fmt.Errorf("revoking user cert error: %w", err)
	}
	if isCertRevoked {
		return nil
	}

	_, err = userService.DataStorage.GetFile(userService.UserDataDirPath + "/" + user.Email)
	if err == nil {
		err = userService.DataStorage.DeleteFile(userService.UserDataDirPath + "/" + user.Email)
		if err != nil {
			return fmt.Errorf("revoking user cert error: %w", err)
		}
	}
	if err != nil {
		if serr, ok := err.(cmerr.NotFoundError); ok {
			errMessage := fmt.Sprintf("revoking user cert error not found: %s", serr.Error())
			return cmerr.NotFoundError{Message: errMessage}
		} else {
			return err
		}
	}

	err = userService.DataStorage.SaveFile(userService.UserDataDirPath+"/"+user.Email+"_revoked", []byte("revoked"))
	if err != nil {
		return fmt.Errorf("revoking user cert error: %w", err)
	}

	err = userService.CertManager.RevokeCert(cert)
	if err != nil {
		return fmt.Errorf("revoking user cert error: %w", err)
	}

	user.IsRevoked = true

	return nil
}

func (userService *UserService) RegisterUser(email string) (*User, *x509.Certificate, error) {
	_, err := userService.DataStorage.GetFile(userService.UserDataDirPath + "/" + email)
	if err == nil {
		return nil, nil, fmt.Errorf("register user error: user already registered")
	}

	user := &User{Email: email}
	userCert, err := userService.GetUserCert(user)
	if err != nil {
		if serr, ok := err.(cmerr.NotFoundError); !ok {
			errMessage := fmt.Errorf("registering user error: %w", serr)
			return nil, nil, cmerr.NotFoundError{Message: errMessage.Error()}
		}
	}

	if userCert == nil {
		userCert, err = userService.generateUserCert(user)
		if err != nil {
			return nil, nil, fmt.Errorf("registering user error: %w", err)
		}
	}

	err = userService.DataStorage.SaveFile(userService.UserDataDirPath+"/"+email, []byte("active"))
	if err != nil {
		return nil, nil, fmt.Errorf("registering user error: %w", err)
	}

	return user, userCert, nil
}

func (userService *UserService) ReinstateUser(user *User) error {
	cert, err := userService.GetUserCert(user)
	if err != nil {
		if _, ok := err.(cmerr.NotFoundError); ok {
			return cmerr.NotFoundError{Message: "reinstating user error: user cert not found"}
		} else {
			return fmt.Errorf("reinstating user error: %w", err)
		}
	}

	isCertRevoked, err := userService.CertManager.IsCertRevoked(cert)
	if err != nil {
		return fmt.Errorf("reinstating user error: %w", err)
	}

	if isCertRevoked {
		_, _, err = userService.CertManager.GenerateCert(user.Email)
		if err != nil {
			return fmt.Errorf("reinstating user error: %w", err)
		}
	}

	err = userService.DataStorage.DeleteFile(userService.UserDataDirPath + "/" + user.Email + "_revoked")
	if err != nil {
		if serr, ok := err.(cmerr.NotFoundError); !ok {
			return fmt.Errorf("reinstating user error: %w", serr)
		}
	}

	err = userService.DataStorage.SaveFile(userService.UserDataDirPath+"/"+user.Email, []byte("active"))
	if err != nil {
		return fmt.Errorf("reinstating user error: %w", err)
	}

	return nil
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

func (userService *UserService) generateUserCert(user *User) (*x509.Certificate, error) {
	cert, _, err := userService.CertManager.GetCert(user.Email)
	if _, isNotFound := err.(cmerr.NotFoundError); err != nil && !isNotFound {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}

	if cert != nil {
		isCertRevoked, err := userService.CertManager.IsCertRevoked(cert)
		if err != nil {
			return nil, fmt.Errorf("generating user cert error: %w", err)
		}
		if isCertRevoked {
			return nil, cmerr.ForbiddenError{Message: "User not allowed to generate cert when the previous one has been revoked"}
		}
	}

	cert, _, err = userService.CertManager.GenerateCert(user.Email)
	if err != nil {
		return nil, fmt.Errorf("generating user cert error: %w", err)
	}

	return cert, nil
}
