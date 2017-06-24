package keepalivego

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/masa23/keepalivego/healthcheck"
	"github.com/mqliang/libipvs"
)

type LVS struct {
	ipvs         libipvs.IPVSHandle
	mu           sync.Mutex
	checkers     *healthcheck.Checkers
	checkResultC chan healthcheck.CheckResult
}

type Config struct {
	LogFile        string              `yaml:"logfile"`
	EnableDebugLog bool                `yaml:"enable_debug_log"`
	VRRP           []ConfigVRRP        `yaml:"vrrp"`
	LVS            []ConfigLVS         `yaml:"lvs"`
	HealthChecks   []ConfigHealthCheck `yaml:"health_check"`
}

type ConfigVRRP struct {
	VRID     int    `yaml:"vrid"`
	Priority int    `yaml:"priority"`
	Address  string `yaml:"address"`
}

type ConfigLVS struct {
	Name     string         `yaml:"name"`
	Port     uint16         `yaml:"port"`
	Address  string         `yaml:"address"`
	Schedule string         `yaml:"schedule"`
	Type     string         `yaml:"type"`
	Servers  []ConfigServer `yaml:"servers"`
}

type ConfigServer struct {
	Port    uint16 `yaml:"port"`
	Address string `yaml:"address"`
	Weight  uint32 `yaml:"weight"`
}

type ConfigHealthCheck struct {
	Address    string        `yaml:"address"`
	URL        string        `yaml:"url"`
	HostHeader string        `yaml:"host_header"`
	OKStatus   int           `yaml:"ok_status"`
	Timeout    time.Duration `yaml:"timeout"`
	Interval   time.Duration `yaml:"interval"`
}

func New() (*LVS, error) {
	ipvs, err := libipvs.New()
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create libipvs handler, err=%v", err)
		}).Stack("")
	}

	return &LVS{
		ipvs:     ipvs,
		checkers: healthcheck.NewCheckers(),
	}, nil
}

func (l *LVS) ReloadConfig(ctx context.Context, config *Config) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ipvsServices, err := l.ipvs.ListServices()
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to list ipvs services, err=%v", err)
		}).Stack("")
	}

	// 不要な設定を削除
	for _, ipvsService := range ipvsServices {
		var serviceConf ConfigLVS
		exist := false
		for _, serviceConf = range config.LVS {
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
	for _, serviceConf := range config.LVS {
		ipAddr := net.ParseIP(serviceConf.Address)
		var ipvsService *libipvs.Service
		exist := false
		for _, ipvsService = range ipvsServices {
			if ipvsService.Address.Equal(ipAddr) {
				exist = true
				break
			}
		}
		family := libipvs.AddressFamily(ipAddressFamily(ipAddr))
		service := libipvs.Service{
			Address:       ipAddr,
			AddressFamily: family,
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
			ipAddr := net.ParseIP(server.Address)
			exist = false
			for _, ipvsDest := range ipvsDests {
				if ipvsDest.Address.Equal(ipAddr) {
					exist = true
					break
				}
			}
			var fwd libipvs.FwdMethod
			switch serviceConf.Type {
			case "dr":
				fwd = libipvs.IP_VS_CONN_F_DROUTE
			case "nat":
				fallthrough
			default:
				fwd = libipvs.IP_VS_CONN_F_MASQ
			}
			family := libipvs.AddressFamily(ipAddressFamily(ipAddr))
			dest := libipvs.Destination{
				Address:       ipAddr,
				AddressFamily: family,
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

	if l.checkers != nil {
		l.doUpdateCheckers(ctx, config)
	}

	return nil
}

func ipAddressFamily(ip net.IP) int {
	if ip.To4() != nil {
		return syscall.AF_INET
	} else {
		return syscall.AF_INET6
	}
}

func (l *LVS) RunHealthCheckLoop(ctx context.Context, config *Config) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.checkResultC = make(chan healthcheck.CheckResult, len(config.HealthChecks))
	l.checkers = healthcheck.NewCheckers()
	l.doUpdateCheckers(ctx, config)

	for {
		select {
		case r := <-l.checkResultC:
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "received healthcheck result").Sprintf("result", "%+v", r).Log()
			}
		case <-ctx.Done():
			return
		}
	}
}

func (l *LVS) doUpdateCheckers(ctx context.Context, config *Config) {
	for _, c := range config.HealthChecks {
		cfg := &healthcheck.Config{
			ServerAddress: c.Address,
			Method:        http.MethodGet,
			URL:           c.URL,
			HostHeader:    c.HostHeader,
			IsOK: func(res *http.Response) (bool, error) {
				return res.StatusCode == c.OKStatus, nil
			},
			Timeout:  c.Timeout,
			Interval: c.Interval,
		}
		l.checkers.AddAndStartChecker(ctx, cfg, l.checkResultC)
	}
}
