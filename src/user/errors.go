package user

type NotFoundError struct {
	error
}

type ForbiddenError struct {
	error
}
