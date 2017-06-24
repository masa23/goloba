package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	yaml "gopkg.in/yaml.v2"

	"github.com/hnakamur/ltsvlog"
	"github.com/masa23/keepalivego"
)

func main() {
	var configfile string
	flag.StringVar(&configfile, "config", "config.yml", "Config File")
	flag.Parse()

	buf, err := ioutil.ReadFile(configfile)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to read config file, err=%v", err)
		}).String("configFile", configfile).Stack(""))
		os.Exit(1)
	}
	var conf keepalivego.Config
	err = yaml.Unmarshal(buf, &conf)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to parse config file, err=%v", err)
		}).String("configFile", configfile).Stack(""))
		os.Exit(1)
	}

	// ログ
	logFile, err := os.OpenFile(conf.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to open log file to write, err=%v", err)
		}).String("logFile", conf.LogFile).Stack(""))
		os.Exit(1)
	}
	defer logFile.Close()
	ltsvlog.Logger = ltsvlog.NewLTSVLogger(logFile, conf.EnableDebugLog)

	ltsvlog.Logger.Info().String("msg", "Start keepalivego!").Log()

	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().Sprintf("config", "%+v", conf).Log()
	}

	lvs, err := keepalivego.New()
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create LVS, err=%v", err)
		}))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigc := make(chan os.Signal, 3)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	go func() {
		for s := range sigc {
			ltsvlog.Logger.Info().String("msg", "Received signal, initiating shutdown...").Stringer("signal", s).Log()
			cancel()
		}
	}()

	err = lvs.ReloadConfig(ctx, &conf)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to reload LVS config, err=%v", err)
		}))
		os.Exit(1)
	}

	lvs.RunHealthCheckLoop(ctx, &conf)
}
