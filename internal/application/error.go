package application

import "fmt"

// ValidationError describes a rejected signing request.
type ValidationError struct {
	Err error
}

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

func invalidRequest(format string, args ...any) error {
	return &ValidationError{Err: fmt.Errorf(format, args...)}
}
