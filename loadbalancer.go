package goloba

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/hnakamur/ltsvlog"
	"github.com/mqliang/libipvs"
)

// LoadBalancer is the load balancer.
type LoadBalancer struct {
	ipvs             libipvs.IPVSHandle
	mu               sync.Mutex
	vrrpNode         *haNode
	servicesAndDests *ipvsServicesAndDests
	checkers         *healthcheckers
	checkResultC     chan healthcheckResult
	config           *Config
}

// Config is the configuration object for the load balancer.
type Config struct {
	LogFile        string           `yaml:"logfile"`
	EnableDebugLog bool             `yaml:"enable_debug_log"`
	StateFile      string           `yaml:"statefile"`
	VRRP           VRRPConfig       `yaml:"vrrp"`
	Services       []*ServiceConfig `yaml:"services"`
}

// VRRPConfig is the configuration about VRRP.
type VRRPConfig struct {
	Enabled              bool          `yaml:"enabled"`
	VRID                 uint8         `yaml:"vrid"`
	Priority             uint8         `yaml:"priority"`
	LocalAddress         string        `yaml:"local_address"`
	RemoteAddress        string        `yaml:"remote_address"`
	Preempt              bool          `yaml:"preempt"`
	MasterAdvertInterval time.Duration `yaml:"master_advert_interval"`
	SendGARPInterval     time.Duration `yaml:"send_garp_interval"`
	VIPInterface         string        `yaml:"vip_interface"`
	VIPs                 []string      `yaml:"vips"`
}

// ServiceConfig is the configuration on the service.
type ServiceConfig struct {
	Name         string               `yaml:"name"`
	Port         uint16               `yaml:"port"`
	Address      string               `yaml:"address"`
	Schedule     string               `yaml:"schedule"`
	Type         string               `yaml:"type"`
	Destinations []*DestinationConfig `yaml:"destinations"`
}

// DestinationConfig is the configuration about the destination.
type DestinationConfig struct {
	Port        uint16             `yaml:"port"`
	Address     string             `yaml:"address"`
	Weight      uint32             `yaml:"weight"`
	HealthCheck *HealthCheckConfig `yaml:"health_check"`

	Detached bool `yaml:"detached"`
	Locked   bool `yaml:"locked"`
}

// HealthCheckConfig is the configuration about the health check.
type HealthCheckConfig struct {
	URL             string        `yaml:"url"`
	HostHeader      string        `yaml:"host_header"`
	EnableKeepAlive bool          `yaml:"enable_keep_alive"`
	SkipVerifyCert  bool          `yaml:"skip_verify_cert"`
	OKStatus        int           `yaml:"ok_status"`
	Timeout         time.Duration `yaml:"timeout"`
	Interval        time.Duration `yaml:"interval"`
}

type ipvsServicesAndDests struct {
	services     []*ipvsServiceAndDests
	destinations map[string]*ipvsDestination
}

type ipvsServiceAndDests struct {
	service      *libipvs.Service
	destinations []*ipvsDestination
}

type ipvsDestination struct {
	destination *libipvs.Destination
	service     *libipvs.Service
}

// ErrInvalidIP is the error which is returned when an IP address is invalid.
var ErrInvalidIP = errors.New("invalid IP address")

func (c *Config) findService(addr string, port uint16) *ServiceConfig {
	for _, s := range c.Services {
		if s.Address == addr && s.Port == port {
			return s
		}
	}
	return nil
}

func (c *Config) findDestination(address string, port uint16) *DestinationConfig {
	for _, s := range c.Services {
		for _, dest := range s.Destinations {
			if dest.Address == address && dest.Port == port {
				return dest
			}
		}
	}
	return nil
}

func (c *ServiceConfig) findDestination(addr string, port uint16) *DestinationConfig {
	for _, d := range c.Destinations {
		if d.Address == addr && d.Port == port {
			return d
		}
	}
	return nil
}

func (s *ipvsServicesAndDests) findService(addr string, port uint16) *ipvsServiceAndDests {
	for _, serviceAndDests := range s.services {
		sv := serviceAndDests.service
		if sv.Address.String() == addr && sv.Port == port {
			return serviceAndDests
		}
	}
	return nil
}

func (s *ipvsServiceAndDests) findDestination(addr string, port uint16) *ipvsDestination {
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

func (s *ipvsServicesAndDests) findDestination(destKey string) *ipvsDestination {
	return s.destinations[destKey]
}

func listServicesAndDests(h libipvs.IPVSHandle) (*ipvsServicesAndDests, error) {
	services, err := h.ListServices()
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to list ipvs services, err=%v", err)
		}).Stack("")
	}
	servicesAndDests := &ipvsServicesAndDests{
		services:     make([]*ipvsServiceAndDests, len(services)),
		destinations: make(map[string]*ipvsDestination),
	}
	for i, service := range services {
		dests, err := h.ListDestinations(service)
		if err != nil {
			return nil, ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to list ipvs destinations, err=%v", err)
			}).Stringer("serviceAddress", service.Address).Stack("")
		}

		serviceAndDests := &ipvsServiceAndDests{
			service:      service,
			destinations: make([]*ipvsDestination, len(dests)),
		}
		for j, dest := range dests {
			destination := &ipvsDestination{destination: dest, service: service}
			destKey := destinationKey(service.Address, service.Port, dest.Address, dest.Port)
			servicesAndDests.destinations[destKey] = destination
			serviceAndDests.destinations[j] = destination
		}
		servicesAndDests.services[i] = serviceAndDests
	}
	return servicesAndDests, nil
}

func (c *Config) totalServiceCount() int {
	cnt := 0
	for _, lvs := range c.Services {
		cnt += len(lvs.Destinations)
	}
	return cnt
}

// New returns a new load balancer.
func New(config *Config) (*LoadBalancer, error) {
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

	return &LoadBalancer{
		config:   config,
		ipvs:     ipvs,
		vrrpNode: node,
		checkers: newHealthcheckers(),
	}, nil
}

func (lb *LoadBalancer) saveState() error {
	data, err := yaml.Marshal(lb.config)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to save goloba state file, err=%v", err)
		}).Stack("")
	}
	err = ioutil.WriteFile(lb.config.StateFile, data, 0666)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to save goloba state file, err=%v", err)
		}).Stack("")
	}
	return nil
}

func newVRRPNode(vrrpCfg *VRRPConfig) (*haNode, error) {
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
	vipCfgs := make([]*haEngineVIPConfig, len(vrrpCfg.VIPs))
	for i, vip := range vrrpCfg.VIPs {
		ip, ipNet, err := net.ParseCIDR(vip)
		if err != nil {
			return nil, ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to parse CIDR %s, err=%v", vip, err)
			}).String("vip", vip).Stack("")
		}
		vipCfgs[i] = &haEngineVIPConfig{ip: ip, ipNet: ipNet}
	}

	haCfg := haConfig{
		Enabled:    true,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Priority:   vrrpCfg.Priority,
		VRID:       vrrpCfg.VRID,
	}
	nc := haNodeConfig{
		haConfig:             haCfg,
		MasterAdvertInterval: vrrpCfg.MasterAdvertInterval,
		Preempt:              vrrpCfg.Preempt,
	}

	conn, err := newIPHAConn(localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	engine := &haEngine{
		config: &haEngineConfig{
			haConfig:         haCfg,
			sendGARPInterval: vrrpCfg.SendGARPInterval,
			vipInterface:     vipIntf,
			vips:             vipCfgs,
		},
	}

	node := newHANode(nc, conn, engine)
	return node, nil
}

// Run runs a load balancer.
func (l *LoadBalancer) Run(ctx context.Context) error {
	err := l.loadConfigOrStateFile(ctx, l.config)
	if err != nil {
		return err
	}
	if l.vrrpNode != nil {
		go l.vrrpNode.run(ctx)
	}
	l.runHealthCheckLoop(ctx, l.config)
	return nil
}

func (l *LoadBalancer) loadConfigOrStateFile(ctx context.Context, config *Config) error {
	if config.StateFile == "" {
		buf, err := ioutil.ReadFile(config.StateFile)
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to read state file, err=%v", err)
			}).String("stateFile", config.StateFile).Stack("")
		}
		var conf Config
		err = yaml.Unmarshal(buf, &conf)
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to parse state file, err=%v", err)
			}).String("stateFile", config.StateFile).Stack("")
		}

		config = &conf
		ltsvlog.Logger.Info().String("msg", "loading config from state file instead of config file").String("stateFile", config.StateFile).Log()
	}

	err := l.reloadConfig(ctx, config)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to load config, err=%v", err)
		})
	}
	return nil
}

func (l *LoadBalancer) reloadConfig(ctx context.Context, config *Config) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	servicesAndDests, err := listServicesAndDests(l.ipvs)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to load ipvs services and destinations, err=%v", err)
		})
	}

	// 配信をなるべく止めたくないので、libipvs.Serverとlibipvs.Destinationの追加・更新を先に行う。
	err = l.doAddOrUpdateIPVS(ctx, config, servicesAndDests)
	if err != nil {
		return err
	}

	// 不要な設定を削除
	err = l.doDeleteIPVS(ctx, config, servicesAndDests)
	if err != nil {
		return err
	}

	servicesAndDests, err = listServicesAndDests(l.ipvs)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to load ipvs services and destinations, err=%v", err)
		})
	}
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "lvs.New").Fmt("servicesAndDests", "%+v", servicesAndDests).Log()
	}
	l.servicesAndDests = servicesAndDests

	if l.checkResultC != nil {
		l.doUpdateCheckers(ctx, config)
	}

	l.config = config
	return nil
}

func (l *LoadBalancer) doAddOrUpdateIPVS(ctx context.Context, config *Config, servicesAndDests *ipvsServicesAndDests) error {
	for _, serviceConf := range config.Services {
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

		for _, destConf := range serviceConf.Destinations {
			err := l.addOrUpdateDestination(ctx, service, serviceAndDests, serviceConf, destConf)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *LoadBalancer) addOrUpdateDestination(ctx context.Context, service *libipvs.Service, serviceAndDests *ipvsServiceAndDests, serviceConf *ServiceConfig, destConf *DestinationConfig) error {
	var fwd libipvs.FwdMethod
	switch serviceConf.Type {
	case "dr":
		fwd = libipvs.IP_VS_CONN_F_DROUTE
	case "nat":
		fallthrough
	default:
		fwd = libipvs.IP_VS_CONN_F_MASQ
	}

	serverIP := net.ParseIP(destConf.Address)
	if serverIP == nil {
		return ltsvlog.WrapErr(ErrInvalidIP, func(err error) error {
			return fmt.Errorf("invalid serverervice IP address, err=%v", err)
		}).String("address", destConf.Address).Stack("")
	}

	var dest *ipvsDestination
	if serviceAndDests != nil {
		dest = serviceAndDests.findDestination(destConf.Address, destConf.Port)
	}

	if dest == nil {
		family := libipvs.AddressFamily(ipAddressFamily(serverIP))
		destination := &libipvs.Destination{
			Address:       serverIP,
			AddressFamily: family,
			Port:          destConf.Port,
			FwdMethod:     fwd,
			Weight:        destConf.Weight,
		}
		err := l.ipvs.NewDestination(service, destination)
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("faild create ipvs destination, err=%s", err)
			}).String("address", destConf.Address).
				Uint16("port", destConf.Port).
				String("fwdMethod", serviceConf.Type).
				Uint32("weight", destConf.Weight).Stack("")
		}
	} else {
		destination := dest.destination
		if fwd != destination.FwdMethod || destConf.Weight != destination.Weight {
			destination.FwdMethod = fwd
			destination.Weight = destConf.Weight
			err := l.ipvs.UpdateDestination(service, destination)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild update ipvs destination, err=%s", err)
				}).String("address", destConf.Address).
					Uint16("port", destConf.Port).
					String("fwdMethod", serviceConf.Type).
					Uint32("weight", destConf.Weight).Stack("")
			}
		}
	}
	return nil
}

func (l *LoadBalancer) doDeleteIPVS(ctx context.Context, config *Config, servicesAndDests *ipvsServicesAndDests) error {
	for _, serviceAndDests := range servicesAndDests.services {
		service := serviceAndDests.service
		serviceConf := config.findService(service.Address.String(), service.Port)
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
				destConf := serviceConf.findDestination(destination.Address.String(), destination.Port)
				if destConf == nil {
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
	return nil
}

func ipAddressFamily(ip net.IP) int {
	if ip.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func (l *LoadBalancer) runHealthCheckLoop(ctx context.Context, config *Config) {
	l.mu.Lock()
	l.checkResultC = make(chan healthcheckResult, config.totalServiceCount())
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

func (l *LoadBalancer) attachOrDetachDestination(ctx context.Context, config *Config, result *healthcheckResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "received healthcheck result").Fmt("result", "%+v", result).Log()
	}

	dest := l.servicesAndDests.findDestination(result.DestinationKey)
	service := dest.service
	destination := dest.destination
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "after findDestination").Fmt("service", "%+v", service).Fmt("destination", "%+v", destination).Log()
	}
	if result.OK && result.Err == nil {
		destConf := config.findDestination(destination.Address.String(), destination.Port)
		if destConf != nil && destination.Weight != destConf.Weight {
			destination.Weight = destConf.Weight
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
			destConf.Detached = false
			err = l.saveState()
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild to save state after attach ipvs destination, err=%s", err)
				}).Stringer("address", destination.Address).
					Uint16("port", destination.Port).
					Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "update state file after attach destination").
				Stringer("address", destination.Address).
				Uint16("port", destination.Port).
				Stringer("fwdMethod", destination.FwdMethod).
				Uint32("weight", destination.Weight).Log()
		}
	} else {
		destConf := config.findDestination(destination.Address.String(), destination.Port)
		if destConf != nil && destination.Weight != 0 {
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
			destConf.Detached = true
			err = l.saveState()
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild to save state after detach ipvs destination, err=%s", err)
				}).Stringer("address", destination.Address).
					Uint16("port", destination.Port).
					Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "update state file after detach destination").
				Stringer("address", destination.Address).
				Uint16("port", destination.Port).Log()
		}
	}
	return nil
}

func (l *LoadBalancer) doUpdateCheckers(ctx context.Context, config *Config) {
	for _, serviceConf := range config.Services {
		for _, destConf := range serviceConf.Destinations {
			c := destConf.HealthCheck
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "doUpdateCheckers").String("serverAddress", destConf.Address).Uint16("serverPort", destConf.Port).Log()
			}
			destKey := destinationKey(net.ParseIP(serviceConf.Address), serviceConf.Port, net.ParseIP(destConf.Address), destConf.Port)
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
