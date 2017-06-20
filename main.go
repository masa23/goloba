package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"syscall"

	yaml "gopkg.in/yaml.v2"

	"github.com/k0kubun/pp"
	"github.com/mqliang/libipvs"
)

const (
	ConfigFile = "./config.yml"
)

type Config struct {
	LogFile string      "yaml:`logfile`"
	Lvs     []ConfigLvs "yaml:`lvs`"
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
	lf, err := os.OpenFile(conf.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("error opening file: ", err.Error())
	}
	defer lf.Close()
	log.SetOutput(lf)
	log.Println("server start")

	ipvs, err := libipvs.New()
	if err != nil {
		log.Fatal("error libipvs load: ", err.Error())
	}

	// IPVS初期化
	if err := ipvs.Flush(); err != nil {
		log.Fatal("error ipvs initialize: ", err.Error())
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
