package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hnakamur/ltsvlog"
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

	// ログ
	errorLogFile, err := os.OpenFile(conf.ErrorLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to open error log file to write, err=%v", err)
		}).String("errorLog", conf.ErrorLog).Stack(""))
		os.Exit(1)
	}
	defer errorLogFile.Close()
	ltsvlog.Logger = ltsvlog.NewLTSVLogger(errorLogFile, conf.EnableDebugLog)

	ltsvlog.Logger.Info().String("msg", "Start goloba!").Log()

	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().Fmt("config", "%+v", conf).Log()
	}

	lb, err := goloba.New(conf)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create LVS, err=%v", err)
		}))
		os.Exit(1)
	}

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err = lb.Run(ctx)
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
