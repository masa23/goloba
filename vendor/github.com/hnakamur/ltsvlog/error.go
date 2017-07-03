package ltsvlog

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Error is an error with label and value pairs.
// *Error implements the error interface so you can
// return *Error as an error.
//
// This is useful when you would like to log an error with
// additional labeled values later at the higher level of
// the callstack.
//
// Error frees lower level functions from depending on loggers
// since Error is just a data structure which holds
// an error, a stacktrace and labeled values.
//
// Please see the example at LTSVLogger.Err for an example usage.
type Error struct {
	error
	originalErr error
	buf         []byte
}

// Err creates an Error with the specified error.
func Err(err error) *Error {
	return &Error{
		error:       err,
		originalErr: err,
		buf:         make([]byte, 0, 8192),
	}
}

// WrapErr wraps an Error or a plain error and returns a new error.
func WrapErr(err error, wrapper func(err error) error) *Error {
	e, ok := err.(*Error)
	if !ok {
		e = Err(err)
	}

	if wrapper != nil {
		e.error = wrapper(e.error)
	}
	return e
}

// Stack appends a stacktrace with label "stack" to Error.
// If label is empty, "stack" is used.
func (e *Error) Stack(label string) *Error {
	e.buf = append(e.buf, '\t')
	if label == "" {
		label = "stack"
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = appendStack(e.buf, 2)
	return e
}

// String appends a labeled string value to Error.
func (e *Error) String(label string, value string) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = append(e.buf, escape(value)...)
	return e
}

// Stringer appends a labeled string value to Error.
// The value will be converted to a string with String() method.
func (e *Error) Stringer(label string, value fmt.Stringer) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = append(e.buf, escape(value.String())...)
	return e
}

// Byte appends a labeled byte value to Error.
func (e *Error) Byte(label string, value byte) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = appendHexByte(e.buf, value)
	return e
}

// Bytes appends a labeled bytes value in hex format to Error.
func (e *Error) Bytes(label string, value []byte) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = appendHexBytes(e.buf, value)
	return e
}

// Fmt appends a labeled formatted string value to Event.
func (e *Error) Fmt(label, format string, a ...interface{}) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = append(e.buf, escape(fmt.Sprintf(format, a...))...)
	return e
}

// DEPRECATED: Use Fmt instead.
//
// Sprintf appends a labeled formatted string value to Error.
func (e *Error) Sprintf(label, format string, a ...interface{}) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = append(e.buf, escape(fmt.Sprintf(format, a...))...)
	return e
}

// Bool appends a labeled bool value to Error.
func (e *Error) Bool(label string, value bool) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendBool(e.buf, value)
	return e
}

// Int appends a labeled int value to Error.
func (e *Error) Int(label string, value int) *Error {
	return e.Int64(label, int64(value))
}

// Int8 appends a labeled int8 value to Error.
func (e *Error) Int8(label string, value int8) *Error {
	return e.Int64(label, int64(value))
}

// Int16 appends a labeled int16 value to Error.
func (e *Error) Int16(label string, value int16) *Error {
	return e.Int64(label, int64(value))
}

// Int32 appends a labeled int32 value to Error.
func (e *Error) Int32(label string, value int32) *Error {
	return e.Int64(label, int64(value))
}

// Int64 appends a labeled int64 value to Error.
func (e *Error) Int64(label string, value int64) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendInt(e.buf, value, 10)
	return e
}

// Uint appends a labeled uint value to Error.
func (e *Error) Uint(label string, value uint) *Error {
	return e.Uint64(label, uint64(value))
}

// Uint8 appends a labeled uint8 value to Error.
func (e *Error) Uint8(label string, value uint8) *Error {
	return e.Uint64(label, uint64(value))
}

// Uint16 appends a labeled uint16 value to Error.
func (e *Error) Uint16(label string, value uint16) *Error {
	return e.Uint64(label, uint64(value))
}

// Uint32 appends a labeled uint32 value to Error.
func (e *Error) Uint32(label string, value uint32) *Error {
	return e.Uint64(label, uint64(value))
}

// Uint64 appends a labeled uint64 value to Error.
func (e *Error) Uint64(label string, value uint64) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendUint(e.buf, value, 10)
	return e
}

// Float32 appends a labeled float32 value to Error.
func (e *Error) Float32(label string, value float32) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendFloat(e.buf, float64(value), 'g', -1, 32)
	return e
}

// Float64 appends a labeled float64 value to Error.
func (e *Error) Float64(label string, value float64) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendFloat(e.buf, value, 'g', -1, 64)
	return e
}

// Time appends a labeled formatted time value to Error.
// The format is the same as that in the Go standard time package.
// If the format is empty, time.RFC3339 is used.
func (e *Error) Time(label string, value time.Time, format string) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	if format == "" {
		format = time.RFC3339
	}
	e.buf = append(e.buf, escape(value.Format(format))...)
	return e
}

// UTCTime appends a labeled time value to Error.
// The time value is converted to UTC and then printed
// in the same format as the log time field, that is
// the ISO8601 format with microsecond precision and
// the timezone "Z".
func (e *Error) UTCTime(label string, value time.Time) *Error {
	e.buf = append(e.buf, '\t')
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = appendUTCTime(e.buf, value)
	return e
}

// Error returns the error string without labeled values.
func (e *Error) Error() string {
	return e.error.Error()
}

// Format formats the error. With "%v" and "%s", just the
// error string is returned. With "%+v", the error string
// with labeled values in LTSV format is returned.
// With "%q", just the quoted error string is returned.
// With "%+q", the quoted error string with labled values
// in LTSV format is returned.
func (e *Error) Format(s fmt.State, c rune) {
	switch c {
	case 'v':
		if s.Flag('+') {
			buf := make([]byte, 0, 8192)
			buf = e.AppendErrorWithValues(buf)
			s.Write(buf)
		} else {
			io.WriteString(s, e.Error())
		}
	case 's':
		io.WriteString(s, e.Error())
	case 'q':
		if s.Flag('+') {
			buf := make([]byte, 0, 8192)
			buf = e.AppendErrorWithValues(buf)
			fmt.Fprintf(s, "%q", buf)
		} else {
			fmt.Fprintf(s, "%q", e.Error())
		}
	}
}

// AppendErrorWithValues appends the error string with labeled values to a byte buffer.
func (e *Error) AppendErrorWithValues(buf []byte) []byte {
	buf = append(buf, "err:"...)
	buf = append(buf, escape(e.Error())...)
	return append(buf, e.buf...)
}

// OriginalError returns the original error.
func (e *Error) OriginalError() error {
	return e.originalErr
}

// appendStack appends a formated stack trace of the calling goroutine to buf
// in one line format which suitable for LTSV logs.
func appendStack(buf []byte, skip int) []byte {
	const maxStackCount = 128
	goPaths := make([]string, 0, maxStackCount)

	addGoPath := func(goPath string) {
		for _, p := range goPaths {
			if goPath == p {
				return
			}
		}
		goPaths = append(goPaths, goPath)
	}

	var pcs [maxStackCount]uintptr
	n := runtime.Callers(0, pcs[:])
	for i := 0; i < n; i++ {
		pc := pcs[i]
		fn := runtime.FuncForPC(pc)
		absPath, line := fn.FileLine(pc)
		name := fn.Name()

		pos := strings.LastIndexByte(name, filepath.Separator)
		pos += strings.IndexByte(name[pos+1:], '.') + 1
		pkg := name[:pos]
		var relPath string
		if pkg == "main" {
			relPath = absPath
			for _, goPath := range goPaths {
				if strings.HasPrefix(absPath, goPath) {
					relPath = absPath[len(goPath):]
					break
				}
			}
		} else {
			pos = strings.LastIndex(absPath, pkg)
			if pos == -1 {
				if strings.HasSuffix(pkg, "_test") {
					pkg = pkg[:len(pkg)-len("_test")]
				}
				pos = strings.LastIndex(absPath, pkg)
				if pos == -1 {
					relPath = absPath
				} else {
					relPath = absPath[pos:]
					goPath := absPath[:pos]
					addGoPath(goPath)
				}
			} else {
				relPath = absPath[pos:]
				goPath := absPath[:pos]
				addGoPath(goPath)
			}
		}

		if i >= skip+1 {
			if i > skip+1 {
				buf = append(buf, ',')
			}
			buf = append(buf, name...)
			buf = append(buf, ' ')
			buf = append(buf, relPath...)
			buf = append(buf, ':')
			buf = strconv.AppendInt(buf, int64(line), 10)
		}
	}
	return buf
}
