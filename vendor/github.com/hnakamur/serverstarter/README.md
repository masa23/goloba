serverstarter  [![Build Status](https://travis-ci.org/hnakamur/serverstarter.png)](https://travis-ci.org/hnakamur/serverstarter) [![Go Report Card](https://goreportcard.com/badge/github.com/hnakamur/serverstarter)](https://goreportcard.com/report/github.com/hnakamur/serverstarter) [![GoDoc](https://godoc.org/github.com/hnakamur/serverstarter?status.svg)](https://godoc.org/github.com/hnakamur/serverstarter)
=============

serverstarter is a Go package which provides a server starter which can be used to do graceful restart.

## A basic example

An example HTTP server which supports graceful restart.

```
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/hnakamur/serverstarter"
)

func main() {
	addr := flag.String("addr", ":8080", "server listen address")
	flag.Parse()

	starter := serverstarter.New()
	if starter.IsMaster() {
		l, err := net.Listen("tcp", *addr)
		if err != nil {
			log.Fatalf("failed to listen %s; %v", *addr, err)
		}
		if err = starter.RunMaster(l); err != nil {
			log.Fatalf("failed to run master; %v", err)
		}
		return
	}

	listeners, err := starter.Listeners()
	if err != nil {
		log.Fatalf("failed to get listeners; %v", err)
	}
	l := listeners[0]

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "from pid %d.\n", os.Getpid())
	})
	srv := &http.Server{}
	go func() { srv.Serve(l) }()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGTERM)
	for {
		if <-sigC == syscall.SIGTERM {
			srv.Shutdown(context.Background())
			return
		}
	}
}
```

## A more advanced example

An example server which listens HTTP/1.1 and HTTP/2.0 ports simultaneously and
supports graceful restart.

### Build and run server

```
cd examples/graceserver
go build -race
./graceserver -http=:8080 -https=:8443 -pidfile=graceserver.pid
```

### Keep repeating graceful restarts

In another terminal, run the following command.

```
cd examples/graceserver
while true; do kill -HUP $(cat graceserver.pid); sleep 1; done
```

### Run the benchmark clients

In another terminal, run the following command.

```
$ cd examples/h2bench
$ go build -race
$ ./h2bench -c 10 -d 1m http://localhost:8080
2017/07/08 09:19:16 starting benchmark: concurrency: 10, time: 1m0s, GOMAXPROCS: 2
2017/07/08 09:20:16 done benchmark: score 121007, elapsed 1m0.006958656s = 2016.549459 / sec
```

Just after running the above command, without waiting the result,
run the following command in another terminal.

```
$ cd examples/h2bench
$ ./h2bench -c 10 -d 1m https://localhost:8443
2017/07/08 09:19:17 starting benchmark: concurrency: 10, time: 1m0s, GOMAXPROCS: 2
2017/07/08 09:20:17 done benchmark: score 34820, elapsed 1m0.00850312s = 580.251101 / sec
```

There is no error in the above output, the graceserver was serving all requests successfully during graceful restarts.

## Credits

* Some code of this package is based on [facebookgo/grace: Graceful restart & zero downtime deploy for Go servers.](https://github.com/facebookgo/grace/)
* `examles/graceserver/main.go` and `examples/h2bench/main.go` is based on [Go1.8のGraceful Shutdownとgo-gracedownの対応 - Shogo's Blog](https://shogo82148.github.io/blog/2017/01/21/golang-1-dot-8-graceful-shutdown/).

Thanks!
