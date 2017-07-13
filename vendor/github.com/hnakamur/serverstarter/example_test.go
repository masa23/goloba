package serverstarter_test

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

func Example() {
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
