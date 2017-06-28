package keepalivego

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/masa23/keepalivego/healthcheck"
	"github.com/mqliang/libipvs"
)

type LVS struct {
	ipvs             libipvs.IPVSHandle
	mu               sync.Mutex
	servicesAndDests *ServicesAndDests
	checkers         *healthcheck.Checkers
	checkResultC     chan healthcheck.CheckResult
}

type Config struct {
	LogFile        string       `yaml:"logfile"`
	EnableDebugLog bool         `yaml:"enable_debug_log"`
	VRRP           []ConfigVRRP `yaml:"vrrp"`
	LVS            []ConfigLVS  `yaml:"lvs"`
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
	Port        uint16            `yaml:"port"`
	Address     string            `yaml:"address"`
	Weight      uint32            `yaml:"weight"`
	HealthCheck ConfigHealthCheck `yaml:"health_check"`
}

type ConfigHealthCheck struct {
	URL            string        `yaml:"url"`
	HostHeader     string        `yaml:"host_header"`
	SkipVerifyCert bool          `yaml:"skip_verify_cert"`
	OKStatus       int           `yaml:"ok_status"`
	Timeout        time.Duration `yaml:"timeout"`
	Interval       time.Duration `yaml:"interval"`
}

type ServicesAndDests struct {
	services     []*ServiceAndDests
	destinations map[string]*Destination
}

type ServiceAndDests struct {
	service      *libipvs.Service
	destinations []*Destination
}

type Destination struct {
	destination *libipvs.Destination
	service     *libipvs.Service
}

func destinationKey(srcIP net.IP, srcPort uint16, destIP net.IP, destPort uint16) string {
	return net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort))) + "," +
		net.JoinHostPort(destIP.String(), strconv.Itoa(int(destPort)))
}

func (s *ServicesAndDests) findDestination(destKey string) *Destination {
	return s.destinations[destKey]
}

func listServicesAndDests(h libipvs.IPVSHandle) (*ServicesAndDests, error) {
	services, err := h.ListServices()
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to list ipvs services, err=%v", err)
		}).Stack("")
	}
	servicesAndDests := &ServicesAndDests{
		services:     make([]*ServiceAndDests, len(services)),
		destinations: make(map[string]*Destination),
	}
	for i, service := range services {
		dests, err := h.ListDestinations(service)
		if err != nil {
			return nil, ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to list ipvs destinations, err=%v", err)
			}).Stringer("serviceAddress", service.Address).Stack("")
		}

		serviceAndDests := &ServiceAndDests{
			service:      service,
			destinations: make([]*Destination, len(dests)),
		}
		for j, dest := range dests {
			destination := &Destination{destination: dest, service: service}
			destKey := destinationKey(service.Address, service.Port, dest.Address, dest.Port)
			servicesAndDests.destinations[destKey] = destination
			serviceAndDests.destinations[j] = destination
		}
		servicesAndDests.services[i] = serviceAndDests
	}
	return servicesAndDests, nil
}

func (c *Config) TotalServerCount() int {
	cnt := 0
	for _, lvs := range c.LVS {
		cnt += len(lvs.Servers)
	}
	return cnt
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

func (l *LVS) Flush() error {
	err := l.ipvs.Flush()
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to flush ipvs services, err=%v", err)
		}).Stack("")
	}
	return nil
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
						return fmt.Errorf("faild update ipvs destination, err=%s", err)
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

	servicesAndDests, err := listServicesAndDests(l.ipvs)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to load ipvs services and destinations, err=%v", err)
		})
	}
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "lvs.New").Sprintf("servicesAndDests", "%+v", servicesAndDests).Log()
	}
	l.servicesAndDests = servicesAndDests

	if l.checkResultC != nil {
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

func findConfigServer(config *Config, address string, port uint16) *ConfigServer {
	for _, lvs := range config.LVS {
		for _, server := range lvs.Servers {
			if server.Address == address && server.Port == port {
				return &server
			}
		}
	}
	return nil
}

func (l *LVS) RunHealthCheckLoop(ctx context.Context, config *Config) {
	l.mu.Lock()
	l.checkResultC = make(chan healthcheck.CheckResult, config.TotalServerCount())
	l.doUpdateCheckers(ctx, config)
	l.mu.Unlock()

	for {
		select {
		case result := <-l.checkResultC:
			err := l.attachOrDetachDestination(ctx, config, &result)
			if err != nil {
				ltsvlog.Logger.Err(err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (l *LVS) attachOrDetachDestination(ctx context.Context, config *Config, result *healthcheck.CheckResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "received healthcheck result").Sprintf("result", "%+v", result).Log()
	}

	dest := l.servicesAndDests.findDestination(result.DestinationKey)
	service := dest.service
	destination := dest.destination
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "after findDestination").Sprintf("service", "%+v", service).Sprintf("destination", "%+v", destination).Log()
	}
	if result.OK && result.Err == nil {
		c := findConfigServer(config, destination.Address.String(), destination.Port)
		if c != nil && destination.Weight != c.Weight {
			destination.Weight = c.Weight
			err := l.ipvs.UpdateDestination(service, destination)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild to attach ipvs destination, err=%s", err)
				}).Stringer("address", destination.Address).
					Uint16("port", destination.Port).
					Stringer("fwdMethod", destination.FwdMethod).
					Uint32("weight", destination.Weight).Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "attached destination").
				Stringer("address", destination.Address).
				Uint16("port", destination.Port).
				Stringer("fwdMethod", destination.FwdMethod).
				Uint32("weight", destination.Weight).Log()
		}
	} else {
		if destination.Weight != 0 {
			destination.Weight = 0
			err := l.ipvs.UpdateDestination(service, destination)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild to detach ipvs destination, err=%s", err)
				}).Stringer("address", destination.Address).
					Uint16("port", destination.Port).
					Stringer("fwdMethod", destination.FwdMethod).
					Uint32("weight", destination.Weight).Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "detached destination").
				Stringer("address", destination.Address).
				Uint16("port", destination.Port).
				Stringer("fwdMethod", destination.FwdMethod).
				Uint32("weight", destination.Weight).Log()
		}
	}
	return nil
}

func (l *LVS) doUpdateCheckers(ctx context.Context, config *Config) {
	for _, lvs := range config.LVS {
		for _, server := range lvs.Servers {
			c := server.HealthCheck
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "doUpdateCheckers").String("serverAddress", server.Address).Uint16("serverPort", server.Port).Log()
			}
			destKey := destinationKey(net.ParseIP(lvs.Address), lvs.Port, net.ParseIP(server.Address), server.Port)
			cfg := &healthcheck.Config{
				DestinationKey: destKey,
				Method:         http.MethodGet,
				URL:            c.URL,
				HostHeader:     c.HostHeader,
				SkipVerifyCert: c.SkipVerifyCert,
				IsOK: func(res *http.Response) (bool, error) {
					if res.StatusCode != c.OKStatus {
						ltsvlog.Logger.Info().String("msg", "healthcheck status unmatch").Int("status", res.StatusCode).Int("okStatus", c.OKStatus).Log()
					}
					return res.StatusCode == c.OKStatus, nil
				},
				Timeout:  c.Timeout,
				Interval: c.Interval,
			}
			l.checkers.AddAndStartChecker(ctx, cfg, l.checkResultC)
		}
	}
}
