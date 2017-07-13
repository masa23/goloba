package goloba

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hnakamur/ltsvlog"
)

type apiServer struct {
	httpServer *http.Server
	done       chan struct{}
}

func (l *LoadBalancer) runAPIServer(ctx context.Context) {
	apiConf := l.config.API
	if apiConf.AccessLog != "" {
		accessLogFile, err := os.OpenFile(apiConf.AccessLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to open API access log file to write, err=%v", err)
			}).String("accessLog", apiConf.AccessLog).Stack(""))
		}
		defer accessLogFile.Close()
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from goloba API server")
	})

	go func() { l.apiServer.httpServer.ListenAndServe() }()
	ltsvlog.Logger.Info().String("msg", "started API server").Log()

	<-ctx.Done()
	ltsvlog.Logger.Info().String("msg", "shutting down API server").Log()
	l.apiServer.httpServer.Shutdown(context.TODO())
	ltsvlog.Logger.Info().String("msg", "finished shutting down API server").Log()
	l.apiServer.done <- struct{}{}
}
