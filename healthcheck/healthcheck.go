package healthcheck

import (
	"context"
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
	ServerAddress string
	Method        string
	URL           string
	HostHeader    string
	IsOK          func(*http.Response) (bool, error)
	Timeout       time.Duration
	Interval      time.Duration
}

type CheckResult struct {
	ServerAddress string
	OK            bool
	Err           error
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

	_, ok := c.checkers[config.ServerAddress]
	if ok {
		return
	}

	checker := NewChecker(config)
	c.checkers[config.ServerAddress] = checker
	go checker.Run(ctx, resultC)
}

func NewChecker(config *Config) *Checker {
	return &Checker{config: config}
}

func (c *Checker) Run(ctx context.Context, resultC chan<- CheckResult) {
	c.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("no direct allowed for healthcheck")
		},
		Timeout: c.config.Timeout,
	}

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ok, err := c.check()
			resultC <- CheckResult{
				ServerAddress: c.config.ServerAddress,
				OK:            ok,
				Err:           err,
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *Checker) check() (bool, error) {
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