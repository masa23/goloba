package webapputil

import "net/http"

// HTTPError is a struct for a HTTP error which contains an error, a HTTP status code, and a detail.
type HTTPError struct {
	Error  error
	Status int
	Detail interface{}
}

// NewHTTPError creates a new HTTPError.
func NewHTTPError(err error, status int, detail interface{}) *HTTPError {
	return &HTTPError{
		Error:  err,
		Status: status,
		Detail: detail,
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
