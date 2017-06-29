package ltsvlog_test

import (
	"errors"
	"fmt"
	"os"

	"github.com/hnakamur/ltsvlog"
)

func ExampleNewLTSVLogger() {
	// Change the global logger to a logger which does not print level values.
	ltsvlog.Logger = ltsvlog.NewLTSVLogger(os.Stdout, true, ltsvlog.SetLevelLabel(""))
	// Output:

	// Actually we don't test the results.
	// This example is added just for document purpose.
}

func ExampleLTSVLogger_Debug() {
	if ltsvlog.Logger.DebugEnabled() {
		n := 234
		ltsvlog.Logger.Debug().String("msg", "This is a debug message").
			String("key", "key1").Int("intValue", n).Log()
	}

	// Output example:
	// time:2017-05-20T19:12:10.883958Z	level:Debug	msg:This is a debug message	key:key1	intValue:234
	// Output:

	// Actually we don't test the results.
	// This example is added just for document purpose.
}

func ExampleLTSVLogger_Info() {
	ltsvlog.Logger.Info().String("msg", "goodbye, world").String("foo", "bar").
		Sprintf("nilValue", "%v", nil).Bytes("bytes", []byte("a/b")).Log()

	// Output example:
	// time:2017-05-20T19:16:11.798840Z	level:Info	msg:goodbye, world	foo:bar	nilValue:<nil>	bytes:0x612f62
	// Output:

	// Actually we don't test the results.
	// This example is added just for document purpose.
}

func ExampleLTSVLogger_Err() {
	b := func() error {
		return ltsvlog.Err(errors.New("some error")).String("key1", "value1").Stack("")
	}
	a := func() error {
		err := b()
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("add explanation here, err=%v", err)
			}).String("key2", "value2")
		}
		return nil

	}
	err := a()
	if err != nil {
		ltsvlog.Logger.Err(err)
	}

	// Output example:
	// time:2017-06-10T13:40:38.344079Z	level:Error	err:add explanation here, err=some error	key1:value1	stack:main.main.func1 github.com/hnakamur/ltsvlog/example/err/main.go:12,main.main.func2 github.com/hnakamur/ltsvlog/example/err/main.go:15,main.main github.com/hnakamur/ltsvlog/example/err/main.go:24,runtime.main runtime/proc.go:194,runtime.goexit runtime/asm_amd64.s:2338	key2:value2
	// Output:

	// Actually we don't test the results.
	// This example is added just for document purpose.
}

func ExampleEvent_String() {
	jsonStr := "{\n\t\"foo\": \"bar\\nbaz\"\n}\n"
	ltsvlog.Logger.Info().String("json", jsonStr).Log()

	// Output example:
	// time:2017-06-10T10:22:48.083226Z        level:Info      json:{\n\t"foo": "bar\\nbaz"\n}\n
	// Output:

	// Actually we don't test the results.
	// This example is added just for document purpose.
}
