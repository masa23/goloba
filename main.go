package main

import (
	"flag"
	"io/ioutil"
	"net"
	"os"
	"syscall"

	yaml "gopkg.in/yaml.v2"

	"github.com/hnakamur/ltsvlog"
	"github.com/mqliang/libipvs"
)

const (
	ConfigFile = "./config.yml"
)

type Config struct {
	LogFile        string       "yaml:`logfile`"
	EnableDebugLog bool         "yaml:`enable_debug_log`"
	Vrrp           []ConfigVrrp "yaml:`vrrp`"
	Lvs            []ConfigLvs  "yaml:`lvs`"
}

type ConfigVrrp struct {
	Vrid     int    "yaml:`vrid`"
	Priority int    "yaml:`priority`"
	Address  string "yaml:`address`"
}

type ConfigLvs struct {
	Name     string         "yaml:`name`"
	Port     uint16         "yaml:`port`"
	Address  string         "yaml:`address`"
	Schedule string         "yaml:`schedule`"
	Type     string         "yaml:`type`"
	Servers  []ConfigServer "yaml:`servers`"
}

type ConfigServer struct {
	Port    uint16 "yaml:`port`"
	Address string "yaml:`address`"
	Weight  uint32 "yaml:`weight`"
}

var conf Config

func main() {
	var configfile string

	flag.StringVar(&configfile, "config", ConfigFile, "Config File")
	flag.Parse()

	buf, err := ioutil.ReadFile(configfile)
	if err != nil {
		panic(err)
	}
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

	ConfigReload(ipvs)
}

func ConfigReload(ipvs libipvs.IPVSHandle) {
	ipvsServices, err := ipvs.ListServices()
	if err != nil {
		panic(err)
	}

	var exist bool

	// 不要な設定を削除
	for _, ipvsService := range ipvsServices {
		var serviceConf ConfigLvs
		exist = false
		for _, serviceConf = range conf.Lvs {
			if ipvsService.Address.Equal(net.ParseIP(serviceConf.Address)) {
				exist = true
				break
			}
		}
		if exist {
			ipvsDests, err := ipvs.ListDestinations(ipvsService)
			if err != nil {
				ltsvlog.Logger.Err(ltsvlog.Err(err).String("msg",
					"faild get serverIpvs list "+ipvsService.Address.String()).Stack(""))
			}
			for _, ipvsDest := range ipvsDests {
				exist = false
				for _, server := range serviceConf.Servers {
					if ipvsDest.Address.Equal(net.ParseIP(server.Address)) {
						exist = true
						break
					}
				}
				if !exist {
					err := ipvs.DelDestination(ipvsService, ipvsDest)
					if err != nil {
						ltsvlog.Logger.Err(ltsvlog.Err(err).String("msg", "faild delete Destination").Stack(""))
					}
				}
			}
		} else {
			err := ipvs.DelService(ipvsService)
			if err != nil {
				ltsvlog.Logger.Err(ltsvlog.Err(err).String("msg", "faild delete "+ipvsService.Address.String()).Stack(""))
			}
			ltsvlog.Logger.Info().String("msg", "delete serviceIpvs "+ipvsService.Address.String()).Log()
		}
	}

	// 設定追加 更新
	for _, serviceConf := range conf.Lvs {
		exist = false
		var ipvsService *libipvs.Service
		for _, ipvsService = range ipvsServices {
			if ipvsService.Address.Equal(net.ParseIP(serviceConf.Address)) {
				exist = true
				break
			}
		}
		service := libipvs.Service{
			Address:       net.ParseIP(serviceConf.Address),
			AddressFamily: syscall.AF_INET,
			Protocol:      libipvs.Protocol(syscall.IPPROTO_TCP),
			Port:          serviceConf.Port,
			SchedName:     libipvs.RoundRobin,
		}
		if !exist {
			if err := ipvs.NewService(&service); err != nil {
				panic(err)
			}
			ipvsService = &service
		} else {
			if err := ipvs.UpdateService(&service); err != nil {
				panic(err)
			}
		}

		ipvsDests, err := ipvs.ListDestinations(ipvsService)
		if err != nil {
			ltsvlog.Logger.Err(ltsvlog.Err(err).String("msg",
				"faild get serverIpvs list "+ipvsService.Address.String()).Stack(""))
		}

		var server ConfigServer
		for _, server = range serviceConf.Servers {
			exist = false
			for _, ipvsDest := range ipvsDests {
				if ipvsDest.Address.Equal(net.ParseIP(server.Address)) {
					exist = true
					break
				}
			}
			var fwd libipvs.FwdMethod
			switch serviceConf.Type {
			case "nat":
				fwd = libipvs.IP_VS_CONN_F_MASQ
			case "dr":
				fwd = libipvs.IP_VS_CONN_F_DROUTE
			default:
				fwd = libipvs.IP_VS_CONN_F_MASQ
			}
			dest := libipvs.Destination{
				Address:       net.ParseIP(server.Address),
				AddressFamily: syscall.AF_INET,
				Port:          server.Port,
				FwdMethod:     fwd,
				Weight:        server.Weight,
			}
			if exist {
				err := ipvs.UpdateDestination(ipvsService, &dest)
				if err != nil {
					panic(err)
				}
			} else {
				err := ipvs.NewDestination(ipvsService, &dest)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}
