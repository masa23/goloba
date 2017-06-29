// Package ltsvlog is a minimalist logging library for writing logs in
// LTSV (Labeled Tab-separated Value) format.
// See http://ltsv.org/ for LTSV.
//
// This logging library has three log levels: Debug, Info and Error.
// The Info and Error levels are always enabled.
// You can disable the Debug level but only when you create a logger.
//
// Each log record is printed as one line. A line has multiple fields
// separated by a tab character. Each field has a label and a value
// which are separated by a colon ':' character.
//
// So you must not contain a colon character in labels.
// This is not checked in this library for performance reason,
// so it is your responsibility not to contain a colon character in labels.
//
// Newline, tab, and backslach characters in values are escaped with
// "\\n", "\\t", and "\\\\" respectively. Show the example for Event.String.
package ltsvlog

import (
	"io"
	"os"
	"strings"
	"time"
)

// LogWriter is a LTSV logger interface
type LogWriter interface {
	DebugEnabled() bool
	Debug() *Event
	Info() *Event
	Err(err error)
}

type appendPrefixFuncType func(buf []byte, level string) []byte

// LTSVLogger is a LTSV logger.
type LTSVLogger struct {
	writer           io.Writer
	debugEnabled     bool
	timeLabel        string
	levelLabel       string
	appendPrefixFunc appendPrefixFuncType
}

// Option is the function type to set an option of LTSVLogger
type Option func(l *LTSVLogger)

// SetTimeLabel returns the option function to set the time label.
// If the label is empty, loggers do not print time values.
func SetTimeLabel(label string) Option {
	return func(l *LTSVLogger) {
		l.timeLabel = label
	}
}

// SetLevelLabel returns the option function to set the level label.
// If the label is empty, loggers do not print level values.
func SetLevelLabel(label string) Option {
	return func(l *LTSVLogger) {
		l.levelLabel = label
	}
}

const (
	defaultTimeLabel  = "time"
	defaultLevelLabel = "level"
)

var defaultappendPrefixFuncType = appendPrefixFunc(defaultTimeLabel, defaultLevelLabel)

// NewLTSVLogger creates a LTSV logger with the default time and value format.
//
// The folloing two values are prepended to each log line.
//
// The first value is the current time, and has the default label "time".
// The time format is RFC3339 with microseconds in UTC timezone.
// This format is the same as "2006-01-02T15:04:05.000000Z" in the
// go time format https://golang.org/pkg/time/#Time.Format
//
// The second value is the log level with the default label "level".
func NewLTSVLogger(w io.Writer, debugEnabled bool, options ...Option) *LTSVLogger {
	l := &LTSVLogger{
		writer:           w,
		debugEnabled:     debugEnabled,
		timeLabel:        defaultTimeLabel,
		levelLabel:       defaultLevelLabel,
		appendPrefixFunc: defaultappendPrefixFuncType,
	}
	for _, o := range options {
		o(l)
	}
	if l.timeLabel != defaultTimeLabel || l.levelLabel != defaultLevelLabel {
		l.appendPrefixFunc = appendPrefixFunc(l.timeLabel, l.levelLabel)
	}
	return l
}

// DebugEnabled returns whether or not the debug level is enabled.
// You can avoid the cost of evaluation of arguments passed to Debug like:
//
//   if ltsvlog.Logger.DebugEnabled() {
//       ltsvlog.Logger.Debug().String("label1", someSlowFunction()).Log()
//   }
func (l *LTSVLogger) DebugEnabled() bool {
	return l.debugEnabled
}

// Debug returns a new Event for writing a Debug level log.
// This Event is returned from the internal event pool, so be sure
// to call Log() to put this event back to the event pool.
//
// Note there still exists the cost of evaluating argument values if the debug level is disabled, even though those arguments are not used.
// So guarding with if and DebugEnabled is recommended.
func (l *LTSVLogger) Debug() *Event {
	ev := eventPool.Get().(*Event)
	ev.logger = l
	ev.enabled = l.debugEnabled
	ev.buf = ev.buf[:0]
	if ev.enabled {
		ev.buf = l.appendPrefixFunc(ev.buf, "Debug")
	}
	return ev
}

// Info returns a new Event for writing a Info level log.
// This Event is returned from the internal event pool, so be sure
// to call Log() to put this event back to the event pool.
func (l *LTSVLogger) Info() *Event {
	ev := eventPool.Get().(*Event)
	ev.logger = l
	ev.enabled = true
	ev.buf = ev.buf[:0]
	ev.buf = l.appendPrefixFunc(ev.buf, "Info")
	return ev
}

// Err writes a log for an error with the error level.
// If err is a *Error, this logs the error with labeled values.
// If err is not a *Error, this logs the error with the label "err".
func (l *LTSVLogger) Err(err error) {
	myErr, ok := err.(*Error)
	if !ok {
		myErr = Err(err)
	}
	buf := make([]byte, 0, 8192)
	buf = l.appendPrefixFunc(buf, "Error")
	buf = myErr.AppendErrorWithValues(buf)
	buf = append(buf, '\n')
	_, _ = l.writer.Write(buf)
}

func appendPrefixFunc(timeLabel, levelLabel string) appendPrefixFuncType {
	if timeLabel != "" && levelLabel != "" {
		return func(buf []byte, level string) []byte {
			buf = append(buf, timeLabel...)
			buf = append(buf, ':')
			now := time.Now().UTC()
			buf = appendUTCTime(buf, now)
			buf = append(buf, '\t')
			buf = append(buf, levelLabel...)
			buf = append(buf, ':')
			buf = append(buf, level...)
			buf = append(buf, '\t')
			return buf
		}
	} else if timeLabel != "" && levelLabel == "" {
		return func(buf []byte, level string) []byte {
			buf = append(buf, timeLabel...)
			buf = append(buf, ':')
			now := time.Now().UTC()
			buf = appendUTCTime(buf, now)
			buf = append(buf, '\t')
			return buf
		}
	} else if timeLabel == "" && levelLabel != "" {
		return func(buf []byte, level string) []byte {
			buf = append(buf, levelLabel...)
			buf = append(buf, ':')
			buf = append(buf, level...)
			buf = append(buf, '\t')
			return buf
		}
	} else {
		return func(buf []byte, level string) []byte {
			return buf
		}
	}
}

func appendUTCTime(buf []byte, t time.Time) []byte {
	t = t.UTC()
	tmp := []byte("0000-00-00T00:00:00.000000Z")
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	itoa(tmp[:4], year, 4)
	itoa(tmp[5:7], int(month), 2)
	itoa(tmp[8:10], day, 2)
	itoa(tmp[11:13], hour, 2)
	itoa(tmp[14:16], min, 2)
	itoa(tmp[17:19], sec, 2)
	itoa(tmp[20:26], t.Nanosecond()/1e3, 6)
	return append(buf, tmp...)
}

// Cheap integer to fixed-width decimal ASCII.  Give a negative width to avoid zero-padding.
// Copied from https://github.com/golang/go/blob/go1.8.1/src/log/log.go#L75-L90
// and modified for ltsvlog.
// It is user's responsibility to pass buf which len(buf) >= wid
func itoa(buf []byte, i int, wid int) {
	// Assemble decimal in reverse order.
	bp := wid - 1
	for i >= 10 || wid > 1 {
		wid--
		q := i / 10
		buf[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	// i < 10
	buf[bp] = byte('0' + i)
}

var escaper = strings.NewReplacer("\t", "\\t", "\n", "\\n", "\\", "\\\\")

func escape(s string) string {
	return escaper.Replace(s)
}

var digits = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func appendHexBytes(buf []byte, v []byte) []byte {
	buf = append(buf, "0x"...)
	for _, b := range v {
		buf = append(buf, digits[b/16])
		buf = append(buf, digits[b%16])
	}
	return buf
}

func appendHexByte(buf []byte, b byte) []byte {
	buf = append(buf, "0x"...)
	buf = append(buf, digits[b/16])
	buf = append(buf, digits[b%16])
	return buf
}

// Logger is the global logger.
// You can change this logger like
// ltsvlog.Logger = ltsvlog.NewLTSVLogger(os.Stdout, false)
// You can change the global logger safely only before writing
// to the logger. Changing the logger while writing may cause
// the unexpected behavior.
var Logger = NewLTSVLogger(os.Stdout, true)

// Discard discards any logging outputs.
type Discard struct{}

// DebugEnabled always return false
func (*Discard) DebugEnabled() bool { return false }

// Debug prints nothing.
// Note there still exists the cost of evaluating argument values, even though they are not used.
// Guarding with if and DebugEnabled is recommended.
func (*Discard) Debug() *Event {
	ev := eventPool.Get().(*Event)
	ev.logger = nil
	ev.enabled = false
	ev.buf = ev.buf[:0]
	return ev
}

// Info prints nothing.
// Note there still exists the cost of evaluating argument values, even though they are not used.
func (*Discard) Info() *Event {
	ev := eventPool.Get().(*Event)
	ev.logger = nil
	ev.enabled = false
	ev.buf = ev.buf[:0]
	return ev
}

// Err prints nothing.
func (*Discard) Err(err error) {}
