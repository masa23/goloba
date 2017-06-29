package ltsvlog

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

var eventPool = &sync.Pool{
	New: func() interface{} {
		return &Event{
			buf: make([]byte, 8192),
		}
	},
}

// Event is a temporary object for building a log record of
// Debug or Info level.
type Event struct {
	logger  *LTSVLogger
	enabled bool
	buf     []byte
}

// String appends a labeled string value to Event.
func (e *Event) String(label string, value string) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = append(e.buf, escape(value)...)
	e.buf = append(e.buf, '\t')
	return e
}

// Stringer appends a labeled string value to Event.
// The value will be converted to a string with String() method.
func (e *Event) Stringer(label string, value fmt.Stringer) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = append(e.buf, escape(value.String())...)
	e.buf = append(e.buf, '\t')
	return e
}

// Bytes appends a labeled bytes value in hex format to Event.
func (e *Event) Bytes(label string, value []byte) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = appendHexBytes(e.buf, value)
	e.buf = append(e.buf, '\t')
	return e
}

// Sprintf appends a labeled formatted string value to Event.
func (e *Event) Sprintf(label, format string, a ...interface{}) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = append(e.buf, escape(fmt.Sprintf(format, a...))...)
	e.buf = append(e.buf, '\t')
	return e
}

// Bool appends a labeled bool value to Event.
func (e *Event) Bool(label string, value bool) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendBool(e.buf, value)
	e.buf = append(e.buf, '\t')
	return e
}

// Byte appends a labeled byte value to Event.
func (e *Event) Byte(label string, value byte) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = appendHexByte(e.buf, value)
	e.buf = append(e.buf, '\t')
	return e
}

// Int appends a labeled int value to Event.
func (e *Event) Int(label string, value int) *Event {
	return e.Int64(label, int64(value))
}

// Int8 appends a labeled int8 value to Event.
func (e *Event) Int8(label string, value int8) *Event {
	return e.Int64(label, int64(value))
}

// Int16 appends a labeled int16 value to Event.
func (e *Event) Int16(label string, value int16) *Event {
	return e.Int64(label, int64(value))
}

// Int32 appends a labeled int32 value to Event.
func (e *Event) Int32(label string, value int32) *Event {
	return e.Int64(label, int64(value))
}

// Int64 appends a labeled int64 value to Event.
func (e *Event) Int64(label string, value int64) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendInt(e.buf, value, 10)
	e.buf = append(e.buf, '\t')
	return e
}

// Uint appends a labeled uint value to Event.
func (e *Event) Uint(label string, value uint) *Event {
	return e.Uint64(label, uint64(value))
}

// Uint8 appends a labeled uint8 value to Event.
func (e *Event) Uint8(label string, value uint8) *Event {
	return e.Uint64(label, uint64(value))
}

// Uint16 appends a labeled uint16 value to Event.
func (e *Event) Uint16(label string, value uint16) *Event {
	return e.Uint64(label, uint64(value))
}

// Uint32 appends a labeled uint32 value to Event.
func (e *Event) Uint32(label string, value uint32) *Event {
	return e.Uint64(label, uint64(value))
}

// Uint64 appends a labeled uint64 value to Event.
func (e *Event) Uint64(label string, value uint64) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendUint(e.buf, value, 10)
	e.buf = append(e.buf, '\t')
	return e
}

// Float32 appends a labeled float32 value to Event.
func (e *Event) Float32(label string, value float32) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendFloat(e.buf, float64(value), 'g', -1, 32)
	e.buf = append(e.buf, '\t')
	return e
}

// Float64 appends a labeled float64 value to Event.
func (e *Event) Float64(label string, value float64) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendFloat(e.buf, value, 'g', -1, 64)
	e.buf = append(e.buf, '\t')
	return e
}

// Time appends a labeled formatted time value to Event.
// The format is the same as that in the Go standard time package.
// If the format is empty, time.RFC3339 is used.
func (e *Event) Time(label string, value time.Time, format string) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	if format == "" {
		format = time.RFC3339
	}
	e.buf = append(e.buf, escape(value.Format(format))...)
	e.buf = append(e.buf, '\t')
	return e
}

// UTCTime appends a labeled UTC time value to Event.
// The time value is converted to UTC and then printed
// in the same format as the log time field, that is
// the ISO8601 format with microsecond precision and
// the timezone "Z".
func (e *Event) UTCTime(label string, value time.Time) *Event {
	if !e.enabled {
		return e
	}
	e.buf = append(e.buf, label...)
	e.buf = append(e.buf, ':')
	e.buf = appendUTCTime(e.buf, value)
	e.buf = append(e.buf, '\t')
	return e
}

// Format formats the error. With "%v" and "%s", labeled values are
// appended to the message in LTSV format.
// With "%q", quoted LTSV format string is returned.
func (e *Event) Format(s fmt.State, c rune) {
	switch c {
	case 'v', 's':
		s.Write(e.buf[:len(e.buf)-1])
	case 'q':
		fmt.Fprintf(s, "%q", e.buf[:len(e.buf)-1])
	}
}

// Log writes this event if the logger which created this event is enabled,
// and puts the event back to the event pool.
func (e *Event) Log() {
	if e.enabled && len(e.buf) > 0 {
		e.buf[len(e.buf)-1] = '\n'
		_, _ = e.logger.writer.Write(e.buf)
	}
	eventPool.Put(e)
}
