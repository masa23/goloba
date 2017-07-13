package goloba

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/hnakamur/webapputil"
)

type apiServer struct {
	httpServer *http.Server
	requestID  uint64
	done       chan struct{}
}

func (l *LoadBalancer) runAPIServer(ctx context.Context, listeners []net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from goloba API server")
	})
	handler := http.Handler(mux)

	apiConf := l.config.API
	if apiConf.AccessLog != "" {
		accessLogFile, err := os.OpenFile(apiConf.AccessLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to open API access log file to write, err=%v", err)
			}).String("accessLog", apiConf.AccessLog).Stack(""))
			return
		}
		defer accessLogFile.Close()

		accessLogger := ltsvlog.NewLTSVLogger(accessLogFile, false, ltsvlog.SetLevelLabel(""))
		writeAccessLog := func(res webapputil.ResponseLogInfo, req *http.Request) {
			accessLogger.Info().String("method", req.Method).Stringer("url", req.URL).
				String("proto", req.Proto).String("host", req.Host).
				String("remoteAddr", req.RemoteAddr).
				String("ua", req.Header.Get("User-Agent")).
				String("reqID", webapputil.RequestID(req)).
				Int("status", res.StatusCode).Int64("sentBodySize", res.SentBodySize).
				Sprintf("elapsed", "%e", res.Elapsed.Seconds()).Log()
		}
		handler = webapputil.AccessLogMiddleware(handler, writeAccessLog)
	}

	requestIDPrefix := append(strconv.AppendInt(nil, time.Now().UnixNano(), 36), '_')
	l.apiServer = &apiServer{
		httpServer: &http.Server{Addr: l.config.API.ListenAddress},
		done:       make(chan struct{}),
	}
	generateRequestID := func(req *http.Request) string {
		id := atomic.AddUint64(&l.apiServer.requestID, 1)
		return string(strconv.AppendUint(requestIDPrefix, id, 36))
	}
	handler = webapputil.RequestIDMiddleware(handler, generateRequestID)
	l.apiServer.httpServer.Handler = handler
	go func() { l.apiServer.httpServer.Serve(listeners[0]) }()
	ltsvlog.Logger.Info().String("msg", "started API server").Log()

	<-ctx.Done()
	ltsvlog.Logger.Info().String("msg", "shutting down API server").Log()
	l.apiServer.httpServer.Shutdown(context.TODO())
	ltsvlog.Logger.Info().String("msg", "finished shutting down API server").Log()
	l.apiServer.done <- struct{}{}
}
