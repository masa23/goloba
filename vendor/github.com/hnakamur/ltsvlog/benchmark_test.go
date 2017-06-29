package ltsvlog_test

import (
	"bytes"
	"errors"
	"io/ioutil"
	"math"
	"os"
	"testing"
	"time"

	"github.com/hnakamur/ltsvlog"
)

func BenchmarkInfo(b *testing.B) {
	tmpfile, err := ioutil.TempFile("", "benchmark")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	logger := ltsvlog.NewLTSVLogger(tmpfile, false)
	for i := 0; i < b.N; i++ {
		logger.Info().String("msg", "hello").String("key1", "value1").Log()
	}
}

func BenchmarkErrWithStackAndUTCTime(b *testing.B) {
	tmpfile, err := ioutil.TempFile("", "benchmark")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	run := func() error {
		return ltsvlog.Err(errors.New("some error")).Stack("stack").UTCTime("errtime", time.Now()).String("key1", "value1")
	}

	logger := ltsvlog.NewLTSVLogger(tmpfile, false)
	for i := 0; i < b.N; i++ {
		err = run()
		logger.Err(err)
	}
}

func BenchmarkErrWithStack(b *testing.B) {
	tmpfile, err := ioutil.TempFile("", "benchmark")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	run := func() error {
		return ltsvlog.Err(errors.New("some error")).Stack("stack").String("key1", "value1")
	}

	logger := ltsvlog.NewLTSVLogger(tmpfile, false)
	for i := 0; i < b.N; i++ {
		err = run()
		logger.Err(err)
	}
}

func BenchmarkErrWithUTCTime(b *testing.B) {
	tmpfile, err := ioutil.TempFile("", "benchmark")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	run := func() error {
		return ltsvlog.Err(errors.New("some error")).UTCTime("errtime", time.Now()).String("key1", "value1")
	}

	logger := ltsvlog.NewLTSVLogger(tmpfile, false)
	for i := 0; i < b.N; i++ {
		err = run()
		logger.Err(err)
	}
}

func BenchmarkEvent_Float32(b *testing.B) {
	buf := new(bytes.Buffer)
	logger := ltsvlog.NewLTSVLogger(buf, true, ltsvlog.SetTimeLabel(""))
	for i := 0; i < b.N; i++ {
		logger.Info().Float32("max_float32", math.MaxFloat32).Float32("smallest_nonzero_float32", math.SmallestNonzeroFloat32).Log()
	}
}

func BenchmarkEvent_Float64(b *testing.B) {
	buf := new(bytes.Buffer)
	logger := ltsvlog.NewLTSVLogger(buf, true, ltsvlog.SetTimeLabel(""))
	for i := 0; i < b.N; i++ {
		logger.Info().Float64("max_float64", math.MaxFloat64).Float64("smallest_nonzero_float64", math.SmallestNonzeroFloat64).Log()
	}
}
