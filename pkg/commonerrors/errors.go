package commonerrors

type NotFoundError struct {
	error
	Message string
}

func (err NotFoundError) Error() string {
	return err.Message
}

type ForbiddenError struct {
	error
	Message string
}

func (err ForbiddenError) Error() string {
	return err.Message
}
