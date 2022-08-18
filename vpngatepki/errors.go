package vpngatepki

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
