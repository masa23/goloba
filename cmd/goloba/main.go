package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/hnakamur/ltsvlog"
	"github.com/hnakamur/serverstarter"
	"github.com/masa23/goloba"
)

func main() {
	var configfile string
	flag.StringVar(&configfile, "config", "config.yml", "Config File")
	flag.Parse()

	conf, err := goloba.LoadConfig(configfile)
	if err != nil {
		ltsvlog.Logger.Err(err)
		os.Exit(1)
	}
	// Setup the error logger
	errorLogFile, err := os.OpenFile(conf.ErrorLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open error log file to write, err=%v\n", err)
		os.Exit(1)
	}
	defer errorLogFile.Close()
	ltsvlog.Logger = ltsvlog.NewLTSVLogger(errorLogFile, conf.EnableDebugLog)

	pid := os.Getpid()
	starter := serverstarter.New()
	if starter.IsMaster() {
		ltsvlog.Logger.Info().String("msg", "goloba master started!").Int("pid", pid).Log()
		if conf.PidFile != "" {
			data := strconv.AppendInt(nil, int64(pid), 10)
			err = ioutil.WriteFile(conf.PidFile, data, 0666)
			if err != nil {
				ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to write pid file; %v", err)
				}).String("pidFile", conf.PidFile))
				os.Exit(2)
			}
		}

		var listeners []net.Listener
		if conf.API.ListenAddress != "" {
			ln, err := net.Listen("tcp", conf.API.ListenAddress)
			if err != nil {
				ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to listen address; %v", err)
				}).String("listenAddress", conf.API.ListenAddress))
				os.Exit(2)
			}
			listeners = append(listeners, ln)
		}

		err = starter.RunMaster(listeners...)
		if err != nil {
			ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to run master; %v", err)
			}).String("listenAddress", conf.API.ListenAddress))
			os.Exit(2)
		}
		return
	}

	ltsvlog.Logger.Info().String("msg", "goloba worker started!").Int("pid", pid).Log()
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().Fmt("config", "%+v", conf).Log()
	}

	listeners, err := starter.Listeners()
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to get listeners, err=%v", err)
		}))
		os.Exit(2)
	} else if len(listeners) == 0 {
		ltsvlog.Logger.Err(errors.New("no listeners"))
		os.Exit(2)
	}

	lb, err := goloba.New(conf)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create load balancer, err=%v", err)
		}))
		os.Exit(2)
	}

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err = lb.Run(ctx, listeners)
		if err != nil {
			ltsvlog.Logger.Err(err)
		}
		done <- struct{}{}
	}()

	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	ltsvlog.Logger.Info().String("msg", "Received SIGTERM, initiating shutdown...").Log()
	cancel()
	<-done
	ltsvlog.Logger.Info().String("msg", "exiting main").Log()
}
