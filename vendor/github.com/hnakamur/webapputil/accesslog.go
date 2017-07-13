package webapputil

import (
	"net/http"
	"time"
)

// ResponseLogInfo contains info for logging a response.
type ResponseLogInfo struct {
	StatusCode   int
	SentBodySize int64
	Elapsed      time.Duration
}

type wrappedResponseWriter struct {
	http.ResponseWriter
	wroteHeader  bool
	code         int
	sentBodySize int64
}

func newWrappedResponseWriter(w http.ResponseWriter) *wrappedResponseWriter {
	return &wrappedResponseWriter{ResponseWriter: w, code: http.StatusOK}
}

func (w *wrappedResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *wrappedResponseWriter) Write(buf []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	w.sentBodySize += int64(len(buf))
	return w.ResponseWriter.Write(buf)
}

// AccessLogMiddleware is a http middleware to write access logs.
func AccessLogMiddleware(next http.Handler, writeLog func(res ResponseLogInfo, req *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		ww := newWrappedResponseWriter(w)
		next.ServeHTTP(ww, r)
		elapsed := time.Since(now)
		res := ResponseLogInfo{
			StatusCode:   ww.code,
			SentBodySize: ww.sentBodySize,
			Elapsed:      elapsed,
		}
		writeLog(res, r)
	})
}
