package main

import (
	"flag"
	"io/ioutil"
	"net"
	"os"
	"syscall"

	yaml "gopkg.in/yaml.v2"

	"github.com/hnakamur/ltsvlog"
	"github.com/k0kubun/pp"
	"github.com/mqliang/libipvs"
)

const (
	ConfigFile = "./config.yml"
)

type Config struct {
	LogFile        string      "yaml:`logfile`"
	EnableDebugLog bool        "yaml:`enable_debug_log`"
	Lvs            []ConfigLvs "yaml:`lvs`"
}

type ConfigLvs struct {
	Name     string          "yaml:`name`"
	Port     uint16          "yaml:`port`"
	Address  string          "yaml:`address`"
	Schedule string          "yaml:`schedule`"
	Type     string          "yaml:`type`"
	Servers  []ConfigServers "yaml:`servers`"
}

type ConfigServers struct {
	Port    uint16 "yaml:`port`"
	Address string "yaml:`address`"
	Weight  uint32 "yaml:`weight`"
}

func main() {
	var configfile string

	flag.StringVar(&configfile, "config", ConfigFile, "Config File")
	flag.Parse()

	buf, err := ioutil.ReadFile(configfile)
	if err != nil {
		panic(err)
	}
	var conf Config
	err = yaml.Unmarshal(buf, &conf)

	// ログ
	logFile, err := os.OpenFile(conf.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()
	ltsvlog.Logger = ltsvlog.NewLTSVLogger(logFile, conf.EnableDebugLog)

	ltsvlog.Logger.Info().String("msg", "Start keepalivego!").Log()

	ipvs, err := libipvs.New()
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(err).String("msg", "faild libipvs load").Stack(""))
	}

	// IPVS初期化
	if err := ipvs.Flush(); err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(err).String("msg", "faild to ipvs initialize").Stack(""))
	}

	// serviceの設定
	for _, service := range conf.Lvs {
		svc := libipvs.Service{
			Address:       net.ParseIP(service.Address),
			AddressFamily: syscall.AF_INET,
			Protocol:      libipvs.Protocol(syscall.IPPROTO_TCP),
			Port:          service.Port,
			SchedName:     libipvs.RoundRobin,
		}

		if err := ipvs.NewService(&svc); err != nil {
			panic(err)
		}

		for _, server := range service.Servers {
			dst := libipvs.Destination{
				Address:       net.ParseIP(server.Address),
				AddressFamily: syscall.AF_INET,
				Port:          server.Port,
				FwdMethod:     libipvs.IP_VS_CONN_F_DROUTE,
			}

			if err := ipvs.NewDestination(&svc, &dst); err != nil {
				panic(err)
			}
		}
	}

	svcs, err := ipvs.ListServices()
	if err != nil {
		panic(err)
	}
	pp.Println(svcs)
}
