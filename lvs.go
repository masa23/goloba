package keepalivego

import (
	"fmt"
	"net"
	"syscall"

	"github.com/hnakamur/ltsvlog"
	"github.com/mqliang/libipvs"
)

type LVS struct {
	ipvs libipvs.IPVSHandle
}

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

func New() (*LVS, error) {
	ipvs, err := libipvs.New()
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create libipvs handler, err=%v", err)
		}).Stack("")
	}

	return &LVS{ipvs: ipvs}, nil
}

func (l *LVS) ReloadConfig(config *Config) error {
	ipvsServices, err := l.ipvs.ListServices()
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to list ipvs services, err=%v", err)
		}).Stack("")
	}

	// 不要な設定を削除
	for _, ipvsService := range ipvsServices {
		var serviceConf ConfigLvs
		exist := false
		for _, serviceConf := range config.Lvs {
			if ipvsService.Address.Equal(net.ParseIP(serviceConf.Address)) {
				exist = true
				break
			}
		}
		if exist {
			ipvsDests, err := l.ipvs.ListDestinations(ipvsService)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to list ipvs destinations, err=%v", err)
				}).Stack("")
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
					err := l.ipvs.DelDestination(ipvsService, ipvsDest)
					if err != nil {
						return ltsvlog.WrapErr(err, func(err error) error {
							return fmt.Errorf("faild delete ipvs destination, err=%v", err)
						}).Stack("")
					}
				}
			}
		} else {
			err := l.ipvs.DelService(ipvsService)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild delete ipvs service, err=%s", err)
				}).Stringer("serviceAddress", ipvsService.Address).Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "deleted ipvs service").Stringer("serviceAddress", ipvsService.Address).Log()
		}
	}

	// 設定追加 更新
	for _, serviceConf := range config.Lvs {
		var ipvsService *libipvs.Service
		exist := false
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
			SchedName:     serviceConf.Schedule,
		}
		if !exist {
			if err := l.ipvs.NewService(&service); err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild create ipvs service, err=%s", err)
				}).String("address", serviceConf.Address).
					Uint16("port", serviceConf.Port).
					String("schedule", serviceConf.Schedule).Stack("")
			}
			ipvsService = &service
		} else {
			if err := l.ipvs.UpdateService(&service); err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild update ipvs service, err=%s", err)
				}).String("address", serviceConf.Address).
					Uint16("port", serviceConf.Port).
					String("schedule", serviceConf.Schedule).Stack("")
			}
		}

		ipvsDests, err := l.ipvs.ListDestinations(ipvsService)
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to list ipvs destinations, err=%v", err)
			}).Stack("")
		}

		for _, server := range serviceConf.Servers {
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
				err := l.ipvs.UpdateDestination(ipvsService, &dest)
				if err != nil {
					return ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("faild create ipvs destination, err=%s", err)
					}).String("address", server.Address).
						Uint16("port", server.Port).
						String("fwdMethod", serviceConf.Type).
						Uint32("weight", server.Weight).Stack("")
				}
			} else {
				err := l.ipvs.NewDestination(ipvsService, &dest)
				if err != nil {
					return ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("faild create ipvs destination, err=%s", err)
					}).String("address", server.Address).
						Uint16("port", server.Port).
						String("fwdMethod", serviceConf.Type).
						Uint32("weight", server.Weight).Stack("")
				}
			}
		}
	}
	return nil
}
