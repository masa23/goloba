// HTTP/1.1 and HTTP/2.0 benchmark client
package main

// Copied from https://shogo82148.github.io/blog/2017/01/21/golang-1-dot-8-graceful-shutdown/

import (
	"crypto/tls"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/kayac/parallel-benchmark/benchmark"
	"golang.org/x/net/http2"
)

type myWorker struct {
	URL    string
	client *http.Client
	buf    []byte
}

func (w *myWorker) Setup() {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        1,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			// テストなので証明書の検証はスキップ
			// プロダクションでは必ず有効にしてください！
			InsecureSkipVerify: true,
		},
		ExpectContinueTimeout: 1 * time.Second,
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		panic(err)
	}
	w.client = &http.Client{
		Transport: tr,
	}
	w.buf = make([]byte, 1024)
}

func (w *myWorker) Teardown() {
}

func (w *myWorker) Process() (subscore int) {
	resp, err := w.client.Get(w.URL)
	if err != nil {
		log.Printf("ERROR: %v", err)
		return 0
	}
	_, err = io.CopyBuffer(ioutil.Discard, resp.Body, w.buf)
	resp.Body.Close()
	if err != nil && err != io.EOF {
		log.Printf("ERROR: %v", err)
		return 0
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Invalid Status: %d", resp.StatusCode)
		return 0
	}
	return 1
}

func main() {
	var (
		conn     int
		duration time.Duration
	)
	flag.IntVar(&conn, "c", 1, "connections to keep open")
	flag.DurationVar(&duration, "d", time.Second, "duration of benchmark")
	flag.Parse()
	url := flag.Args()[0]
	workers := make([]benchmark.Worker, conn)
	for i, _ := range workers {
		workers[i] = &myWorker{URL: url}
	}
	benchmark.Run(workers, duration)
}
