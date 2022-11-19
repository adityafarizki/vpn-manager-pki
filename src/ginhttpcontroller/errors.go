package ginhttpcontroller

import "io/fs"

func getErrorCode(err error) int {
	switch err.(type) {
	case *NotFoundError:
		return 404
	case *UnauthorizedError:
		return 403
	default:
		return 400
	}
}

func handleError(err error) error {
	switch err.(type) {
	case *fs.PathError:
		return &NotFoundError{message: err.Error()}
	default:
		return err
	}
}

type NotFoundError struct {
	message string
}

func (err *NotFoundError) Error() string {
	return err.message
}

type UnauthorizedError struct {
	message string
}

func (err *UnauthorizedError) Error() string {
	return err.message
}
