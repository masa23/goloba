ltsvlog [![Build Status](https://travis-ci.org/hnakamur/ltsvlog.png)](https://travis-ci.org/hnakamur/ltsvlog) [![Go Report Card](https://goreportcard.com/badge/github.com/hnakamur/ltsvlog)](https://goreportcard.com/report/github.com/hnakamur/ltsvlog) [![GoDoc](https://godoc.org/github.com/hnakamur/ltsvlog?status.svg)](https://godoc.org/github.com/hnakamur/ltsvlog) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/hyperium/hyper/master/LICENSE)
=======

ltsvlog is a minimalist [LTSV; Labeled Tab-separated Values](http://ltsv.org/) logging library in Go.
See https://godoc.org/github.com/hnakamur/ltsvlog for the API document.

I wrote a blog article about this library in Japanese: [GoでLTSV形式でログ出力するライブラリを書いた · hnakamur's blog at github](http://hnakamur.github.io/blog/2016/06/13/wrote_go_ltsvlog_library/).

## An example code and output

An example code:

```
package main

import (
	"errors"
	"fmt"

	"github.com/hnakamur/ltsvlog"
)

func main() {
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "This is a debug message").
			String("str", "foo").Int("int", 234).Log()
	}

	ltsvlog.Logger.Info().Sprintf("float1", "%3.2f", 3.14).Log()

	err := a()
	if err != nil {
		ltsvlog.Logger.Err(err)
	}
}

func a() error {
	err := b()
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("add explanation here, err=%v", err)
		})
	}
	return nil
}

func b() error {
	return ltsvlog.Err(errors.New("some error")).String("key1", "value1").Stack("")
}
```

An example output:

```
time:2017-06-01T16:52:33.959833Z	level:Debug	msg:This is a debug message	str:foo	int:234
time:2017-06-01T16:52:33.959862Z	level:Info	float1:3.14
time:2017-06-01T16:52:33.959914Z	level:Error	err:add explanation here, err=some error       key1:value1     stack:main.b github.com/hnakamur/ltsvlog/example/main.go:43,main.a github.com/hnakamur/ltsvlog/example/main.go:33,main.main github.com/hnakamur/ltsvlog/example/main.go:21,runtime.main runtime/proc.go:194,runtime.goexit runtime/asm_amd64.s:2338
```

Since these log lines ar long, please scroll horizontally to the right to see all the output.

## Benchmark result
[hnakamur/go-log-benchmarks](https://github.com/hnakamur/go-log-benchmarks)

## License
MIT
