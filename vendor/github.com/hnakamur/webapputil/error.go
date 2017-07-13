package webapputil

import "net/http"

// HTTPError represents a ltsvlog.Error and HTTP status code and status text.
type HTTPError struct {
	Error  error
	Status int
}

// NewHTTPError creates a new HTTPError.
func NewHTTPError(err error, status int) *HTTPError {
	return &HTTPError{
		Error:  err,
		Status: status,
	}
}

// WithErrorHandler returns a new HTTP handler which handles errors
// returned from the next handler.
func WithErrorHandler(next func(w http.ResponseWriter, r *http.Request) *HTTPError, handler func(err *HTTPError, w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := next(w, r)
		if err != nil {
			handler(err, w, r)
		}
	})
}
