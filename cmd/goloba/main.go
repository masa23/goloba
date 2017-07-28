package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/hnakamur/ltsvlog"
	"github.com/hnakamur/serverstarter"
	"github.com/masa23/goloba"
)

func main() {
	configPath := flag.String("config", "/etc/goloba/goloba.yml", "Config file path")
	checkConfigOnly := flag.Bool("t", false, "check config and exit")
	flag.Parse()

	conf, err := goloba.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	if *checkConfigOnly {
		fmt.Fprintf(os.Stderr, "config check OK\n")
		return
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
	starter := serverstarter.New(serverstarter.SetGracefulShutdownSignalToChild(syscall.SIGUSR1))
	if starter.IsMaster() {
		err = runMaster(starter, conf, pid)
		if err != nil {
			ltsvlog.Logger.Err(err)
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
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)
	sig := <-signals
	switch sig {
	case syscall.SIGUSR1:
		ltsvlog.Logger.Info().String("msg", "worker received SIGUSR1, initiating shutdown...").Int("pid", pid).Log()
		lb.SetKeepVIPsDuringRestart(true)
		cancel()
	case syscall.SIGINT, syscall.SIGTERM:
		ltsvlog.Logger.Info().String("msg", "worker received SIGINT or SIGTERM, initiating shutdown...").Stringer("signal", sig).Int("pid", pid).Log()
		cancel()
	}
	<-done
	ltsvlog.Logger.Info().String("msg", "goloba worker stopped").Int("pid", pid).Log()
}

func runMaster(starter *serverstarter.Starter, conf *goloba.Config, pid int) error {
	err := writePIDFile(conf.PIDFile, pid)
	if err != nil {
		return err
	}
	defer func() {
		os.Remove(conf.PIDFile)
		ltsvlog.Logger.Info().String("msg", "goloba master stopped").Int("pid", pid).Log()
	}()

	ltsvlog.Logger.Info().String("msg", "goloba master started!").Int("pid", pid).Log()

	var listeners []net.Listener
	if conf.API.ListenAddress != "" {
		ln, err := net.Listen("tcp", conf.API.ListenAddress)
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to listen address; %v", err)
			}).String("listenAddress", conf.API.ListenAddress)
		}
		listeners = append(listeners, ln)
	}

	err = starter.RunMaster(listeners...)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to run master; %v", err)
		}).String("listenAddress", conf.API.ListenAddress)
	}
	return nil
}

func writePIDFile(path string, pid int) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to open PID file for writing; %v", err)
		}).Stack("")
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "%d\n", pid)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to write PID file; %v", err)
		}).Stack("")
	}
	return nil
}
