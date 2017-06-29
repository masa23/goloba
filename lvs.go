package keepalivego

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/masa23/keepalivego/vrrp"
	"github.com/mqliang/libipvs"
)

type LVS struct {
	ipvs             libipvs.IPVSHandle
	mu               sync.Mutex
	vrrpNode         *vrrp.Node
	servicesAndDests *ServicesAndDests
	checkers         *healthcheckers
	checkResultC     chan healthcheckResult
}

type Config struct {
	LogFile        string      `yaml:"logfile"`
	EnableDebugLog bool        `yaml:"enable_debug_log"`
	VRRP           ConfigVRRP  `yaml:"vrrp"`
	LVS            []ConfigLVS `yaml:"lvs"`
}

type ConfigVRRP struct {
	Enabled              bool          `yaml:"enabled"`
	VRID                 uint8         `yaml:"vrid"`
	Priority             uint8         `yaml:"priority"`
	LocalAddress         string        `yaml:"local_address"`
	RemoteAddress        string        `yaml:"remote_address"`
	Preempt              bool          `yaml:"preempt"`
	MasterAdvertInterval time.Duration `yaml:"master_advert_interval"`
	VIPInterface         string        `yaml:"vip_interface"`
	VIPs                 []string      `yaml:"vips"`
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
	URL             string        `yaml:"url"`
	HostHeader      string        `yaml:"host_header"`
	EnableKeepAlive bool          `yaml:"enable_keep_alive"`
	SkipVerifyCert  bool          `yaml:"skip_verify_cert"`
	OKStatus        int           `yaml:"ok_status"`
	Timeout         time.Duration `yaml:"timeout"`
	Interval        time.Duration `yaml:"interval"`
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

var ErrInvalidIP = errors.New("invalid IP address")

func (c *Config) findLVS(addr string, port uint16) *ConfigLVS {
	for _, lvs := range c.LVS {
		if lvs.Address == addr && lvs.Port == port {
			return &lvs
		}
	}
	return nil
}

func (c *ConfigLVS) findServer(addr string, port uint16) *ConfigServer {
	for _, s := range c.Servers {
		if s.Address == addr && s.Port == port {
			return &s
		}
	}
	return nil
}

func (s *ServicesAndDests) findService(addr string, port uint16) *ServiceAndDests {
	for _, serviceAndDests := range s.services {
		sv := serviceAndDests.service
		if sv.Address.String() == addr && sv.Port == port {
			return serviceAndDests
		}
	}
	return nil
}

func (s *ServiceAndDests) findDestination(addr string, port uint16) *Destination {
	for _, destination := range s.destinations {
		d := destination.destination
		if d.Address.String() == addr && d.Port == port {
			return destination
		}
	}
	return nil
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

func New(config *Config) (*LVS, error) {
	ipvs, err := libipvs.New()
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create libipvs handler, err=%v", err)
		}).Stack("")
	}

	node, err := newVRRPNode(&config.VRRP)
	if err != nil {
		return nil, err
	}

	return &LVS{
		ipvs:     ipvs,
		vrrpNode: node,
		checkers: newHealthcheckers(),
	}, nil
}

func newVRRPNode(vrrpCfg *ConfigVRRP) (*vrrp.Node, error) {
	if !vrrpCfg.Enabled {
		return nil, nil
	}

	localAddr := net.ParseIP(vrrpCfg.LocalAddress)
	if localAddr == nil {
		return nil, ltsvlog.Err(fmt.Errorf("invalid local IP address (%s)", vrrpCfg.LocalAddress)).
			String("localAddress", vrrpCfg.LocalAddress).Stack("")
	}

	remoteAddr := net.ParseIP(vrrpCfg.RemoteAddress)
	if remoteAddr == nil {
		return nil, ltsvlog.Err(fmt.Errorf("invalid remote IP address (%s)", vrrpCfg.LocalAddress)).
			String("remoteAddress", vrrpCfg.LocalAddress).Stack("")
	}

	vipIntf, err := net.InterfaceByName(vrrpCfg.VIPInterface)
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("interface not found for name=%s, err=%v", vrrpCfg.VIPInterface, err)
		}).String("vipInterface", vrrpCfg.VIPInterface).Stack("")
	}
	vipCfgs := make([]*vrrp.VIPsHAConfigVIP, len(vrrpCfg.VIPs))
	for i, vip := range vrrpCfg.VIPs {
		ip, ipNet, err := net.ParseCIDR(vip)
		if err != nil {
			return nil, ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to parse CIDR %s, err=%v", vip, err)
			}).String("vip", vip).Stack("")
		}
		vipCfgs[i] = &vrrp.VIPsHAConfigVIP{IP: ip, IPNet: ipNet}
	}

	haConfig := vrrp.HAConfig{
		Enabled:    true,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Priority:   vrrpCfg.Priority,
		VRID:       vrrpCfg.VRID,
	}
	nc := vrrp.NodeConfig{
		HAConfig:             haConfig,
		MasterAdvertInterval: vrrpCfg.MasterAdvertInterval,
		Preempt:              vrrpCfg.Preempt,
	}

	conn, err := vrrp.NewIPHAConn(localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	engine := &vrrp.VIPsUpdateEngine{
		Config: &vrrp.VIPsHAConfig{
			HAConfig:     haConfig,
			VIPInterface: vipIntf,
			VIPs:         vipCfgs,
		},
	}

	node := vrrp.NewNode(nc, conn, engine)
	return node, nil
}

func (l *LVS) ShutdownVRRPNode() {
	l.vrrpNode.Shutdown()
}

func (l *LVS) RunVRRPNode() {
	l.vrrpNode.Run()
}

func (l *LVS) ReloadConfig(ctx context.Context, config *Config) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	servicesAndDests, err := listServicesAndDests(l.ipvs)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to load ipvs services and destinations, err=%v", err)
		})
	}

	// 配信をなるべく止めたくないので、libipvs.Serverとlibipvs.Destinationの追加・更新を先に行う。
	for _, serviceConf := range config.LVS {
		ipAddr := net.ParseIP(serviceConf.Address)
		if ipAddr == nil {
			return ltsvlog.WrapErr(ErrInvalidIP, func(err error) error {
				return fmt.Errorf("invalid service IP address, err=%v", err)
			}).String("address", serviceConf.Address).Stack("")
		}
		var service *libipvs.Service
		serviceAndDests := servicesAndDests.findService(serviceConf.Address, serviceConf.Port)
		if serviceAndDests == nil {
			family := libipvs.AddressFamily(ipAddressFamily(ipAddr))
			service = &libipvs.Service{
				Address:       ipAddr,
				AddressFamily: family,
				Protocol:      libipvs.Protocol(syscall.IPPROTO_TCP),
				Port:          serviceConf.Port,
				SchedName:     serviceConf.Schedule,
			}
			if err := l.ipvs.NewService(service); err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild create ipvs service, err=%s", err)
				}).String("address", serviceConf.Address).
					Uint16("port", serviceConf.Port).
					String("schedule", serviceConf.Schedule).Stack("")
			}
		} else {
			service = serviceAndDests.service
			if serviceConf.Schedule != service.SchedName {
				service.SchedName = serviceConf.Schedule
				if err := l.ipvs.UpdateService(service); err != nil {
					return ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("faild update ipvs service, err=%s", err)
					}).String("address", serviceConf.Address).
						Uint16("port", serviceConf.Port).
						String("schedule", serviceConf.Schedule).Stack("")
				}

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

		for _, serverConf := range serviceConf.Servers {
			serverIP := net.ParseIP(serverConf.Address)
			if serverIP == nil {
				return ltsvlog.WrapErr(ErrInvalidIP, func(err error) error {
					return fmt.Errorf("invalid serverervice IP address, err=%v", err)
				}).String("address", serverConf.Address).Stack("")
			}

			var dest *Destination
			if serviceAndDests != nil {
				dest = serviceAndDests.findDestination(serverConf.Address, serverConf.Port)
			}

			if dest == nil {
				family := libipvs.AddressFamily(ipAddressFamily(serverIP))
				destination := &libipvs.Destination{
					Address:       serverIP,
					AddressFamily: family,
					Port:          serverConf.Port,
					FwdMethod:     fwd,
					Weight:        serverConf.Weight,
				}
				err := l.ipvs.NewDestination(service, destination)
				if err != nil {
					return ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("faild create ipvs destination, err=%s", err)
					}).String("address", serverConf.Address).
						Uint16("port", serverConf.Port).
						String("fwdMethod", serviceConf.Type).
						Uint32("weight", serverConf.Weight).Stack("")
				}
			} else {
				destination := dest.destination
				if fwd != destination.FwdMethod || serverConf.Weight != destination.Weight {
					destination.FwdMethod = fwd
					destination.Weight = serverConf.Weight
					err := l.ipvs.UpdateDestination(service, destination)
					if err != nil {
						return ltsvlog.WrapErr(err, func(err error) error {
							return fmt.Errorf("faild update ipvs destination, err=%s", err)
						}).String("address", serverConf.Address).
							Uint16("port", serverConf.Port).
							String("fwdMethod", serviceConf.Type).
							Uint32("weight", serverConf.Weight).Stack("")
					}
				}
			}
		}
	}

	// 不要な設定を削除
	for _, serviceAndDests := range servicesAndDests.services {
		service := serviceAndDests.service
		serviceConf := config.findLVS(service.Address.String(), service.Port)
		if serviceConf == nil {
			for _, dest := range serviceAndDests.destinations {
				destination := dest.destination
				err := l.ipvs.DelDestination(service, destination)
				if err != nil {
					return ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("faild delete ipvs destination, err=%v", err)
					}).Stack("")
				}
			}

			err := l.ipvs.DelService(service)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild delete ipvs service, err=%s", err)
				}).Stringer("serviceAddress", service.Address).Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "deleted ipvs service").Stringer("serviceAddress", service.Address).Log()
		} else {
			for _, dest := range serviceAndDests.destinations {
				destination := dest.destination
				serverConf := serviceConf.findServer(destination.Address.String(), destination.Port)
				if serverConf == nil {
					err := l.ipvs.DelDestination(service, destination)
					if err != nil {
						return ltsvlog.WrapErr(err, func(err error) error {
							return fmt.Errorf("faild delete ipvs destination, err=%v", err)
						}).Stack("")
					}
				}
			}
		}
	}

	servicesAndDests, err = listServicesAndDests(l.ipvs)
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
	l.checkResultC = make(chan healthcheckResult, config.TotalServerCount())
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

func (l *LVS) attachOrDetachDestination(ctx context.Context, config *Config, result *healthcheckResult) error {
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
			cfg := &healthcheckerConfig{
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
			l.checkers.startHealthchecker(ctx, cfg, l.checkResultC)
		}
	}
}
