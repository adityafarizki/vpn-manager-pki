package certmanager

type NotFoundError struct {
	error
	Message string
}

func (err NotFoundError) Error() string {
	return err.Message
}
