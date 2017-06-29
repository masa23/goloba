package ltsvlog

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"regexp"
	"testing"
	"time"
)

func TestLTSVLogger_Err(t *testing.T) {
	buf := new(bytes.Buffer)
	// We don't print time fields to make it easy to compare test results.
	logger := NewLTSVLogger(buf, true, SetTimeLabel(""))

	testCases := []struct {
		name string
		f    func(l *LTSVLogger)
		want string
	}{
		{
			name: "string",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).String("str", "foo"))
			},
			want: "level:Error\terr:some error\tstr:foo\n",
		},
		{
			name: "stringer",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Stringer("value", big.NewInt(123)))
			},
			want: "level:Error\terr:some error\tvalue:123\n",
		},
		{
			name: "bool",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Bool("active", true).Bool("enabled", false))
			},
			want: "level:Error\terr:some error\tactive:true\tenabled:false\n",
		},
		{
			name: "byte",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Byte("byte", 'b'))
			},
			want: "level:Error\terr:some error\tbyte:0x62\n",
		},
		{
			name: "bytes",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Bytes("bytes", []byte("\t\n")))
			},
			want: "level:Error\terr:some error\tbytes:0x090a\n",
		},
		{
			name: "float32",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Float32("max_float32", math.MaxFloat32).Float32("smallest_nonzero_float32", math.SmallestNonzeroFloat32))
			},
			want: "level:Error\terr:some error\tmax_float32:3.4028235e+38\tsmallest_nonzero_float32:1e-45\n",
		},
		{
			name: "float64",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Float64("max_float64", math.MaxFloat64).Float64("smallest_nonzero_float64", math.SmallestNonzeroFloat64))
			},
			want: "level:Error\terr:some error\tmax_float64:1.7976931348623157e+308\tsmallest_nonzero_float64:5e-324\n",
		},
		{
			name: "int",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Int("zero", 0).Int("max_int32", math.MaxInt32))
			},
			want: "level:Error\terr:some error\tzero:0\tmax_int32:2147483647\n",
		},
		{
			name: "int8",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Int("min_int8", math.MinInt8).Int("max_int8", math.MaxInt8))
			},
			want: "level:Error\terr:some error\tmin_int8:-128\tmax_int8:127\n",
		},
		{
			name: "int16",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Int("min_int16", math.MinInt16).Int("max_int16", math.MaxInt16))
			},
			want: "level:Error\terr:some error\tmin_int16:-32768\tmax_int16:32767\n",
		},
		{
			name: "int32",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Int("min_int32", math.MinInt32).Int("max_int32", math.MaxInt32))
			},
			want: "level:Error\terr:some error\tmin_int32:-2147483648\tmax_int32:2147483647\n",
		},
		{
			name: "int64",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Int("min_int64", math.MinInt64).Int("max_int64", math.MaxInt64))
			},
			want: "level:Error\terr:some error\tmin_int64:-9223372036854775808\tmax_int64:9223372036854775807\n",
		},
		{
			name: "uint",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Uint("zero", 0).Uint("max_uint32", math.MaxUint32))
			},
			want: "level:Error\terr:some error\tzero:0\tmax_uint32:4294967295\n",
		},
		{
			name: "uint8",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Uint("min_uint8", 0).Uint("max_uint8", math.MaxUint8))
			},
			want: "level:Error\terr:some error\tmin_uint8:0\tmax_uint8:255\n",
		},
		{
			name: "uint16",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Uint("min_uint16", 0).Uint("max_uint16", math.MaxUint16))
			},
			want: "level:Error\terr:some error\tmin_uint16:0\tmax_uint16:65535\n",
		},
		{
			name: "uint32",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Uint("min_uint32", 0).Uint("max_uint32", math.MaxUint32))
			},
			want: "level:Error\terr:some error\tmin_uint32:0\tmax_uint32:4294967295\n",
		},
		{
			name: "uint64",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Uint("min_uint64", 0).Uint("max_uint64", math.MaxUint64))
			},
			want: "level:Error\terr:some error\tmin_uint64:0\tmax_uint64:18446744073709551615\n",
		},
		{
			name: "sprintf",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")).Sprintf("pi", "%.2f", math.Pi))
			},
			want: "level:Error\terr:some error\tpi:3.14\n",
		},
		{
			name: "rfc822z_time",
			f: func(l *LTSVLogger) {
				t := time.Date(2017, 5, 21, 12, 44, 56, 987654321, time.UTC)
				l.Err(Err(errors.New("some error")).Time("time2", t, time.RFC822Z))
			},
			want: "level:Error\terr:some error\ttime2:21 May 17 12:44 +0000\n",
		},
		{
			name: "utc_time",
			f: func(l *LTSVLogger) {
				t := time.Date(2017, 5, 21, 12, 44, 56, 987654321, time.UTC)
				l.Err(Err(errors.New("some error")).UTCTime("time2", t))
			},
			want: "level:Error\terr:some error\ttime2:2017-05-21T12:44:56.987654Z\n",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			tc.f(logger)
			got := buf.String()
			if got != tc.want {
				t.Errorf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestLTSVLogger_Err_NoLevel(t *testing.T) {
	buf := new(bytes.Buffer)
	// We don't print time fields to make it easy to compare test results.
	logger := NewLTSVLogger(buf, true, SetTimeLabel(""), SetLevelLabel(""))

	testCases := []struct {
		name string
		f    func(l *LTSVLogger)
		want string
	}{
		{
			name: "error_only",
			f: func(l *LTSVLogger) {
				l.Err(Err(errors.New("some error")))
			},
			want: "err:some error\n",
		},
		{
			name: "plain_error",
			f: func(l *LTSVLogger) {
				l.Err(errors.New("some error"))
			},
			want: "err:some error\n",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			tc.f(logger)
			got := buf.String()
			if got != tc.want {
				t.Errorf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestError_Stack(t *testing.T) {
	buf := new(bytes.Buffer)
	// We don't print time fields to make it easy to compare test results.
	logger := NewLTSVLogger(buf, true, SetTimeLabel(""))
	logger.Err(Err(errors.New("some error")).Stack(""))
	got := buf.String()
	wantRegex := "^level:Error\terr:some error\tstack:github.com/hnakamur/ltsvlog\\.TestError_Stack github\\.com/hnakamur/ltsvlog/error_test.go:\\d+,.*\n$"
	matched, err := regexp.MatchString(wantRegex, got)
	if err != nil {
		t.Fatalf("got error from regexp.MatchString, got=%q, err=%v", got, err)
	}
	if !matched {
		t.Errorf("got %q; wantRegex %q", got, wantRegex)
	}
}
