package healthcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/hnakamur/ltsvlog"
)

type Config struct {
	DestinationKey string
	Method         string
	URL            string
	HostHeader     string
	SkipVerifyCert bool
	IsOK           func(*http.Response) (bool, error)
	Timeout        time.Duration
	Interval       time.Duration
}

type CheckResult struct {
	DestinationKey string
	OK             bool
	Err            error
}

type Checkers struct {
	checkers map[string]*Checker
	mu       sync.Mutex
}

type Checker struct {
	config *Config
	client *http.Client
}

func NewCheckers() *Checkers {
	return &Checkers{
		checkers: make(map[string]*Checker),
	}
}

func (c *Checkers) AddAndStartChecker(ctx context.Context, config *Config, resultC chan<- CheckResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := config.DestinationKey
	_, ok := c.checkers[key]
	if ok {
		return
	}

	checker := NewChecker(config)
	c.checkers[key] = checker
	go checker.Run(ctx, resultC)
}

func NewChecker(config *Config) *Checker {
	return &Checker{config: config}
}

func (c *Checker) Run(ctx context.Context, resultC chan<- CheckResult) {
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "Checker.Run").Sprintf("config", "%+v", c.config).Log()
	}
	var tr http.RoundTripper
	if c.config.SkipVerifyCert {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		tr = http.DefaultTransport
	}
	c.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("no direct allowed for healthcheck")
		},
		Timeout:   c.config.Timeout,
		Transport: tr,
	}

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ok, err := c.check()
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "before sending result in Checker.Run").String("destKey", c.config.DestinationKey).Bool("ok", ok).Sprintf("err", "%+v", err).Log()
			}
			resultC <- CheckResult{
				DestinationKey: c.config.DestinationKey,
				OK:             ok,
				Err:            err,
			}
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "after sending result in Checker.Run").String("destKey", c.config.DestinationKey).Bool("ok", ok).Sprintf("err", "%+v", err).Log()
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *Checker) check() (bool, error) {
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "Checker.check").Sprintf("config", "%+v", c.config).Log()
	}
	req, err := http.NewRequest(c.config.Method, c.config.URL, nil)
	if err != nil {
		return false, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create request, err=%v", err)
		}).String("method", c.config.Method).String("url", c.config.URL).Stack("")
	}
	if c.config.HostHeader != "" {
		req.Host = c.config.HostHeader
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to send request, err=%v", err)
		}).String("method", c.config.Method).String("url", c.config.URL).Stack("")
	}
	defer resp.Body.Close()

	ok, err := c.config.IsOK(resp)
	if err != nil {
		err = ltsvlog.WrapErr(err, nil).
			String("method", c.config.Method).String("url", c.config.URL)
	}
	_, err2 := io.Copy(ioutil.Discard, resp.Body)
	if err == nil && err2 != nil {
		err = ltsvlog.WrapErr(err2, func(err error) error {
			return fmt.Errorf("failed to read response body, err=%v", err)
		}).String("method", c.config.Method).String("url", c.config.URL).Stack("")
	}
	return ok, err
}
