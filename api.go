package goloba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/hnakamur/webapputil"
	"github.com/hnakamur/webapputil/problem"
)

type apiServer struct {
	httpServer *http.Server
	requestID  uint64
	done       chan struct{}
}

func (l *LoadBalancer) runAPIServer(ctx context.Context, listeners []net.Listener) {
	mux := http.NewServeMux()
	mux.Handle("/attach", wrapWithErrHandler(l.handleAttach))
	mux.Handle("/detach", wrapWithErrHandler(l.handleDetach))
	mux.Handle("/unlock", wrapWithErrHandler(l.handleUnlock))
	mux.HandleFunc("/info", l.handleInfo)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from goloba API server\n")
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

func wrapWithErrHandler(next func(w http.ResponseWriter, r *http.Request) *webapputil.HTTPError) http.Handler {
	return webapputil.WithErrorHandler(next, errorHandler)
}

func errorHandler(hErr *webapputil.HTTPError, w http.ResponseWriter, r *http.Request) {
	ltsvlog.Err(hErr.Error)
	err := problem.SendProblem(w, hErr.Status, hErr.Detail)
	if err != nil {
		ltsvlog.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to send problem; %v", err)
		}))
	}
}

func (l *LoadBalancer) handleAttach(w http.ResponseWriter, r *http.Request) *webapputil.HTTPError {
	hErr := parseForm(r)
	if hErr != nil {
		return hErr
	}
	serviceIP, servicePort, hErr := getAddressParam(r, "service")
	if hErr != nil {
		return hErr
	}
	destIP, destPort, hErr := getAddressParam(r, "dest")
	if hErr != nil {
		return hErr
	}
	lock, hErr := getBoolParam(r, "lock", true)
	if hErr != nil {
		return hErr
	}
	err := l.attachOrDetachDestinationByAPI(context.TODO(), serviceIP, servicePort, destIP, destPort, true, lock)
	if err != nil {
		return webapputil.NewHTTPError(err, http.StatusInternalServerError, problem.Problem{
			Type:  "https://goloba.github.io/problems/internal-server-error",
			Title: "failed to attach destination",
		})
	}
	sendOKResponse(w, r, struct {
		Message     string `json:"message"`
		Service     string `json:"service"`
		Destination string `json:"destination"`
		Locked      bool   `json:"locked"`
	}{
		Message:     "attached destination",
		Service:     fmt.Sprintf("%s:%d", serviceIP, servicePort),
		Destination: fmt.Sprintf("%s:%d", destIP, destPort),
		Locked:      lock,
	})
	return nil
}

func (l *LoadBalancer) handleDetach(w http.ResponseWriter, r *http.Request) *webapputil.HTTPError {
	hErr := parseForm(r)
	if hErr != nil {
		return hErr
	}
	serviceIP, servicePort, hErr := getAddressParam(r, "service")
	if hErr != nil {
		return hErr
	}
	destIP, destPort, hErr := getAddressParam(r, "dest")
	if hErr != nil {
		return hErr
	}
	lock, hErr := getBoolParam(r, "lock", true)
	if hErr != nil {
		return hErr
	}
	err := l.attachOrDetachDestinationByAPI(context.TODO(), serviceIP, servicePort, destIP, destPort, false, lock)
	if err != nil {
		return webapputil.NewHTTPError(err, http.StatusInternalServerError, problem.Problem{
			Type:  "https://goloba.github.io/problems/internal-server-error",
			Title: "failed to detach destination",
		})
	}
	sendOKResponse(w, r, struct {
		Message     string `json:"message"`
		Service     string `json:"service"`
		Destination string `json:"destination"`
		Locked      bool   `json:"locked"`
	}{
		Message:     "detached destination",
		Service:     fmt.Sprintf("%s:%d", serviceIP, servicePort),
		Destination: fmt.Sprintf("%s:%d", destIP, destPort),
		Locked:      lock,
	})
	return nil
}

func (l *LoadBalancer) handleUnlock(w http.ResponseWriter, r *http.Request) *webapputil.HTTPError {
	hErr := parseForm(r)
	if hErr != nil {
		return hErr
	}
	serviceIP, servicePort, hErr := getAddressParam(r, "service")
	if hErr != nil {
		return hErr
	}
	destIP, destPort, hErr := getAddressParam(r, "dest")
	if hErr != nil {
		return hErr
	}
	err := l.unlockDestination(context.TODO(), serviceIP, servicePort, destIP, destPort)
	if err != nil {
		return webapputil.NewHTTPError(err, http.StatusInternalServerError, problem.Problem{
			Type:  "https://goloba.github.io/problems/internal-server-error",
			Title: "failed to unlock destination",
		})
	}
	sendOKResponse(w, r, struct {
		Message     string `json:"message"`
		Service     string `json:"service"`
		Destination string `json:"destination"`
	}{
		Message:     "unlocked destination",
		Service:     fmt.Sprintf("%s:%d", serviceIP, servicePort),
		Destination: fmt.Sprintf("%s:%d", destIP, destPort),
	})
	return nil
}

func parseForm(r *http.Request) *webapputil.HTTPError {
	err := r.ParseForm()
	if err != nil {
		err = ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to parse query and form parameters")
		}).Stack("")
		return webapputil.NewHTTPError(err, http.StatusBadRequest, problem.Problem{
			Type:  "https://goloba.github.io/problems/bad-request",
			Title: "failed to parse query and form parameters",
		})
	}
	return nil
}

type invalidParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func getBoolParam(r *http.Request, name string, defaultValue bool) (bool, *webapputil.HTTPError) {
	strVal := r.Form.Get(name)
	if strVal == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseBool(strVal)
	if err != nil {
		err = ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to parse boolean value")
		}).Stack("")
		return false, webapputil.NewHTTPError(err, http.StatusBadRequest,
			struct {
				problem.Problem
				InvalidParams []invalidParam `json:"invalid-params"`
			}{
				Problem: problem.Problem{
					Type:  "https://goloba.github.io/problems/bad-request",
					Title: "failed to parse bool parameter",
				},
				InvalidParams: []invalidParam{
					{Name: name, Value: strVal},
				},
			})
	}
	return value, nil
}

func getAddressParam(r *http.Request, name string) (net.IP, uint16, *webapputil.HTTPError) {
	strVal := r.Form.Get(name)
	host, portStr, err := net.SplitHostPort(strVal)
	if err != nil {
		err = ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("address must be in <IPAddr>:<port> form")
		}).Stack("")
		return nil, 0, webapputil.NewHTTPError(err, http.StatusBadRequest,
			struct {
				problem.Problem
				InvalidParams []invalidParam `json:"invalid-params"`
			}{
				Problem: problem.Problem{
					Type:  "https://goloba.github.io/problems/bad-request",
					Title: "failed to parse bool parameter",
				},
				InvalidParams: []invalidParam{
					{Name: name, Value: strVal},
				},
			})
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		err = ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("address must be in <IPAddr>:<port> form")
		}).Stack("")
		return nil, 0, webapputil.NewHTTPError(err, http.StatusBadRequest,
			struct {
				problem.Problem
				InvalidParams []invalidParam `json:"invalid-params"`
			}{
				Problem: problem.Problem{
					Type:  "https://goloba.github.io/problems/bad-request",
					Title: "port must be integer",
				},
				InvalidParams: []invalidParam{
					{Name: name, Value: strVal},
				},
			})
	}
	if port < 0 || 65535 < port {
		err = ltsvlog.Err(errors.New("bad port in address")).Stack("")
		return nil, 0, webapputil.NewHTTPError(err, http.StatusBadRequest,
			struct {
				problem.Problem
				InvalidParams []invalidParam `json:"invalid-params"`
			}{
				Problem: problem.Problem{
					Type:  "https://goloba.github.io/problems/bad-request",
					Title: "port must be integer between 0 and 65535",
				},
				InvalidParams: []invalidParam{
					{Name: name, Value: strVal},
				},
			})
	}

	ip := net.ParseIP(host)
	if ip == nil {
		err = ltsvlog.Err(errors.New("bad IP address")).Stack("")
		return nil, 0, webapputil.NewHTTPError(err, http.StatusBadRequest,
			struct {
				problem.Problem
				InvalidParams []invalidParam `json:"invalid-params"`
			}{
				Problem: problem.Problem{
					Type:  "https://goloba.github.io/problems/bad-request",
					Title: "address must be a valid IP address",
				},
				InvalidParams: []invalidParam{
					{Name: name, Value: strVal},
				},
			})
	}
	return ip, uint16(port), nil
}

func sendOKResponse(w http.ResponseWriter, r *http.Request, detail interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	err := enc.Encode(detail)
	if err != nil {
		ltsvlog.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to write ok response; %v", err)
		}).String("requestID", webapputil.RequestID(r)).Stack(""))
	}
}

func (l *LoadBalancer) handleInfo(w http.ResponseWriter, r *http.Request) {
	// ipvsadm output:
	// [root@lbvm01 ~]# ipvsadm -Ln
	// IP Virtual Server version 1.2.1 (size=4096)
	// Prot LocalAddress:Port Scheduler Flags
	//   -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
	// TCP  192.168.122.2:80 wrr
	//   -> 192.168.122.62:80            Route   100    0          0
	//   -> 192.168.122.240:80           Route   500    0          0
	// TCP  192.168.122.2:443 wrr
	//   -> 192.168.122.62:443           Masq    10     0          0
	//   -> 192.168.122.240:443          Masq    20     0          0
	//
	// goloba output:
	// [root@lbvm01 ~]# curl localhost:8880/info
	// Prot LocalAddress:Port Scheduler Flags
	//   -> RemoteAddress:Port           Forward Weight ActiveConn InActConn Detached Locked
	// tcp  192.168.122.2:80 wrr
	//   -> 192.168.122.62:80            droute  100    0          0         true     false
	//   -> 192.168.122.240:80           droute  500    0          0         false    false
	// tcp  192.168.122.2:443 wrr
	//   -> 192.168.122.62:443           masq    10     0          0         true     false
	//   -> 192.168.122.240:443          masq    20     0          0         false    false

	l.mu.RLock()
	defer l.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Prot LocalAddress:Port Scheduler Flags\n")
	fmt.Fprintf(w, "  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn Detached Locked\n")
	for _, serviceAndDests := range l.servicesAndDests.services {
		s := serviceAndDests.service
		serviceConf := l.config.findService(s.Address, s.Port)
		fmt.Fprintf(w, "%-4s %s:%d %s\n", s.Protocol, s.Address, s.Port, s.SchedName)
		for _, dest := range serviceAndDests.destinations {
			d := dest.destination
			destConf := serviceConf.findDestination(d.Address, d.Port)
			hostPort := net.JoinHostPort(d.Address.String(), strconv.Itoa(int(d.Port)))
			fmt.Fprintf(w, "  -> %-28s %-7s %-6d %-10d %-9d %-8v %v\n", hostPort, d.FwdMethod, destConf.Weight, d.ActiveConns, d.InactConns, destConf.Detached, destConf.Locked)
		}
	}
}
