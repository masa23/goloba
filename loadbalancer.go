package goloba

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/hnakamur/ltsvlog"
	"github.com/hnakamur/netutil"
	"github.com/mqliang/libipvs"
)

// MaxWeight is the maximum value for the destination weight.
// The minimum value is zero.
const MaxWeight = 65535

// LoadBalancer is the load balancer.
type LoadBalancer struct {
	ipvs             libipvs.IPVSHandle
	mu               sync.RWMutex
	vrrpNode         *haNode
	servicesAndDests *ipvsServicesAndDests
	checkers         *healthcheckers
	checkResultC     chan healthcheckResult
	apiServer        *apiServer
	config           *Config
}

// Config is the configuration object for the load balancer.
type Config struct {
	PIDFile        string          `yaml:"pid_file"`
	ErrorLog       string          `yaml:"error_log"`
	EnableDebugLog bool            `yaml:"enable_debug_log"`
	API            APIConfig       `yaml:"api"`
	VRRP           VRRPConfig      `yaml:"vrrp"`
	Services       []ServiceConfig `yaml:"services"`

	destinations map[string]*DestinationConfig `yaml:"-"`
}

// APIConfig is the configuration about API server.
type APIConfig struct {
	ListenAddress string `yaml:"listen_address"`
	AccessLog     string `yaml:"access_log"`
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
	Name         string              `yaml:"name"`
	Address      netutil.IP          `yaml:"address"`
	Port         uint16              `yaml:"port"`
	Schedule     string              `yaml:"schedule"`
	Type         string              `yaml:"type"`
	Destinations []DestinationConfig `yaml:"destinations"`
}

// DestinationConfig is the configuration about the destination.
type DestinationConfig struct {
	Address     netutil.IP        `yaml:"address"`
	Port        uint16            `yaml:"port"`
	Weight      uint16            `yaml:"weight"`
	HealthCheck HealthCheckConfig `yaml:"health_check"`

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

// LoadConfig loads the configuration from a file.
func LoadConfig(file string) (*Config, error) {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to read config file, err=%v", err)
		}).String("configFile", file).Stack("")
	}
	var c Config
	err = yaml.Unmarshal(buf, &c)
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to parse config file, err=%v", err)
		}).String("configFile", file).Stack("")
	}
	c.updateDestinations()
	return &c, nil
}

func (c *Config) updateDestinations() {
	c.destinations = make(map[string]*DestinationConfig)
	for i := range c.Services {
		s := &c.Services[i]
		for j := range s.Destinations {
			dest := &s.Destinations[j]
			key := destinationKey(net.IP(s.Address), s.Port, net.IP(dest.Address), dest.Port)
			c.destinations[key] = dest
		}
	}
}

func (c *Config) findService(addr net.IP, port uint16) *ServiceConfig {
	for i := range c.Services {
		s := &c.Services[i]
		if net.IP(s.Address).Equal(addr) && s.Port == port {
			return s
		}
	}
	return nil
}

func (c *Config) findDestination(destKey string) *DestinationConfig {
	return c.destinations[destKey]
}

func (c *ServiceConfig) findDestination(addr net.IP, port uint16) *DestinationConfig {
	for i := range c.Destinations {
		d := &c.Destinations[i]
		if net.IP(d.Address).Equal(addr) && d.Port == port {
			return d
		}
	}
	return nil
}

func (s *ipvsServicesAndDests) findService(addr net.IP, port uint16) *ipvsServiceAndDests {
	for _, serviceAndDests := range s.services {
		sv := serviceAndDests.service
		if sv.Address.Equal(addr) && sv.Port == port {
			return serviceAndDests
		}
	}
	return nil
}

func (s *ipvsServiceAndDests) findDestination(addr net.IP, port uint16) *ipvsDestination {
	for _, destination := range s.destinations {
		d := destination.destination
		if d.Address.Equal(addr) && d.Port == port {
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
		sort.Sort(ipvsDestinationsByIPAndPort(serviceAndDests.destinations))
		servicesAndDests.services[i] = serviceAndDests
	}
	sort.Sort(ipvsServiceAndDestsByIPAndPort(servicesAndDests.services))
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
func (l *LoadBalancer) Run(ctx context.Context, listeners []net.Listener) error {
	err := l.applyConfig(ctx, l.config)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to load config, err=%v", err)
		})
	}
	if l.vrrpNode != nil {
		go l.vrrpNode.run(ctx)
	}
	go l.runHealthCheckLoop(ctx, l.config)
	if l.config.API.ListenAddress != "" {
		go l.runAPIServer(ctx, listeners)
	}
	<-ctx.Done()
	if l.config.API.ListenAddress != "" {
		if ltsvlog.Logger.DebugEnabled() {
			ltsvlog.Logger.Debug().String("msg", "waiting API server to shutdown").Log()
		}
		<-l.apiServer.done
	}
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "exiting Run").Log()
	}
	return nil
}

func (l *LoadBalancer) applyConfig(ctx context.Context, config *Config) error {
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

	err = l.loadIPVS()
	if err != nil {
		return err
	}

	if l.checkResultC != nil {
		l.doUpdateCheckers(ctx, config)
	}

	l.config = config
	return nil
}

func (l *LoadBalancer) loadIPVS() error {
	servicesAndDests, err := listServicesAndDests(l.ipvs)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to load ipvs services and destinations, err=%v", err)
		})
	}
	if ltsvlog.Logger.DebugEnabled() {
		ltsvlog.Logger.Debug().String("msg", "lvs.New").Fmt("servicesAndDests", "%+v", servicesAndDests).Log()
	}
	l.servicesAndDests = servicesAndDests
	return nil
}

func (l *LoadBalancer) doAddOrUpdateIPVS(ctx context.Context, config *Config, servicesAndDests *ipvsServicesAndDests) error {
	for i := range config.Services {
		serviceConf := &config.Services[i]
		var service *libipvs.Service
		serviceConfIP := net.IP(serviceConf.Address)
		serviceAndDests := servicesAndDests.findService(serviceConfIP, serviceConf.Port)
		if serviceAndDests == nil {
			family := libipvs.AddressFamily(ipAddressFamily(serviceConfIP))
			service = &libipvs.Service{
				Address:       serviceConfIP,
				AddressFamily: family,
				Protocol:      libipvs.Protocol(syscall.IPPROTO_TCP),
				Port:          serviceConf.Port,
				SchedName:     serviceConf.Schedule,
			}
			err := l.ipvs.NewService(service)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to create ipvs service, err=%s", err)
				}).Stringer("srcIP", serviceConfIP).Uint16("srcPort", serviceConf.Port).
					String("schedule", serviceConf.Schedule).Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "added ipvs service").
				Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).
				String("schedule", serviceConf.Schedule).Log()
		} else {
			service = serviceAndDests.service
			if serviceConf.Schedule != service.SchedName {
				service.SchedName = serviceConf.Schedule
				err := l.ipvs.UpdateService(service)
				if err != nil {
					return ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("failed to update ipvs service, err=%s", err)
					}).Stringer("srcIP", serviceConfIP).Uint16("srcPort", serviceConf.Port).
						String("schedule", serviceConf.Schedule).Stack("")
				}
				ltsvlog.Logger.Info().String("msg", "updated ipvs service").
					Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).
					String("schedule", serviceConf.Schedule).Log()
			}
		}

		for j := range serviceConf.Destinations {
			destConf := &serviceConf.Destinations[j]
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

	destConfIP := net.IP(destConf.Address)

	var dest *ipvsDestination
	if serviceAndDests != nil {
		dest = serviceAndDests.findDestination(destConfIP, destConf.Port)
	}
	if dest == nil {
		family := libipvs.AddressFamily(ipAddressFamily(destConfIP))
		destination := &libipvs.Destination{
			Address:       destConfIP,
			AddressFamily: family,
			Port:          destConf.Port,
			FwdMethod:     fwd,
			Weight:        uint32(destConf.Weight),
		}
		err := l.ipvs.NewDestination(service, destination)
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to create ipvs destination, err=%s", err)
			}).Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).
				Stringer("destIP", destConfIP).Uint16("destPort", destConf.Port).
				String("fwdMethod", serviceConf.Type).Uint16("weight", destConf.Weight).Stack("")
		}
		ltsvlog.Logger.Info().String("msg", "added ipvs destination").
			Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).
			Stringer("destIP", destConfIP).Uint16("destPort", destConf.Port).
			String("fwdMethod", serviceConf.Type).Uint16("weight", destConf.Weight).Log()
	} else {
		destination := dest.destination
		if fwd != destination.FwdMethod || uint32(destConf.Weight) != destination.Weight {
			destination.FwdMethod = fwd
			destination.Weight = uint32(destConf.Weight)
			err := l.ipvs.UpdateDestination(service, destination)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to update ipvs destination, err=%s", err)
				}).Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).
					Stringer("destIP", destConfIP).Uint16("destPort", destConf.Port).
					String("fwdMethod", serviceConf.Type).Uint16("weight", destConf.Weight).Stack("")
			}
			ltsvlog.Logger.Info().String("msg", "updated ipvs destination").
				Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).
				Stringer("destIP", destConfIP).Uint16("destPort", destConf.Port).
				String("fwdMethod", serviceConf.Type).Uint16("weight", destConf.Weight).Log()
		}
	}
	return nil
}

func (l *LoadBalancer) doDeleteIPVS(ctx context.Context, config *Config, servicesAndDests *ipvsServicesAndDests) error {
	for _, serviceAndDests := range servicesAndDests.services {
		service := serviceAndDests.service
		serviceConf := config.findService(service.Address, service.Port)
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
			ltsvlog.Logger.Info().String("msg", "deleted ipvs service").
				Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).Log()
		} else {
			for _, dest := range serviceAndDests.destinations {
				destination := dest.destination
				destConf := serviceConf.findDestination(net.IP(destination.Address), destination.Port)
				if destConf == nil {
					err := l.ipvs.DelDestination(service, destination)
					if err != nil {
						return ltsvlog.WrapErr(err, func(err error) error {
							return fmt.Errorf("faild delete ipvs destination, err=%v", err)
						}).Stack("")
					}
					ltsvlog.Logger.Info().String("msg", "deleted ipvs destination").
						Stringer("srcIP", service.Address).Uint16("srcPort", service.Port).
						Stringer("destIP", destination.Address).Uint16("destPort", destination.Port).Log()
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
			err := l.attachOrDetachDestinationByHealthCheck(ctx, config, &result)
			if err != nil {
				ltsvlog.Logger.Err(err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (l *LoadBalancer) attachOrDetachDestinationByHealthCheck(ctx context.Context, config *Config, result *healthcheckResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	err := l.loadIPVS()
	if err != nil {
		return err
	}

	dest := l.servicesAndDests.findDestination(result.DestinationKey)
	service := dest.service
	destination := dest.destination
	destConf := config.findDestination(result.DestinationKey)
	if destConf == nil {
		return ltsvlog.Err(errors.New("destination config not found for healthcheck")).
			Stringer("srvIP", service.Address).
			Uint16("srvPort", service.Port).
			Stringer("destIP", destination.Address).
			Uint16("destPort", destination.Port).Stack("")
	}
	if result.OK && result.Err == nil {
		if destination.Weight != uint32(destConf.Weight) {
			if destConf.Locked {
				if ltsvlog.Logger.DebugEnabled() {
					ltsvlog.Logger.Debug().String("msg", "skip attaching locked destination").
						Stringer("srvIP", service.Address).
						Uint16("srvPort", service.Port).
						Stringer("destIP", destination.Address).
						Uint16("destPort", destination.Port).Log()
				}
				return nil
			}

			destination.Weight = uint32(destConf.Weight)
			err := l.ipvs.UpdateDestination(service, destination)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild to attach ipvs destination, err=%s", err)
				}).Stringer("srvIP", service.Address).
					Uint16("srvPort", service.Port).
					Stringer("destIP", destination.Address).
					Uint16("destPort", destination.Port).
					Uint16("cfgWeight", destConf.Weight).
					Stack("")
			}
			destConf.Detached = false
			ltsvlog.Logger.Info().String("msg", "attached destination").
				Stringer("srvIP", service.Address).
				Uint16("srvPort", service.Port).
				Stringer("destIP", destination.Address).
				Uint16("destPort", destination.Port).
				Uint16("cfgWeight", destConf.Weight).Log()
		}
	} else {
		if destination.Weight != 0 {
			if destConf.Locked {
				if ltsvlog.Logger.DebugEnabled() {
					ltsvlog.Logger.Debug().String("msg", "skip detaching locked destination").
						Stringer("srvIP", service.Address).
						Uint16("srvPort", service.Port).
						Stringer("destIP", destination.Address).
						Uint16("destPort", destination.Port).Log()
				}
				return nil
			}

			destination.Weight = 0
			err := l.ipvs.UpdateDestination(service, destination)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("faild to detach ipvs destination, err=%s", err)
				}).Stringer("srvIP", service.Address).
					Uint16("srvPort", service.Port).
					Stringer("destIP", destination.Address).
					Uint16("destPort", destination.Port).
					Uint16("cfgWeight", destConf.Weight).
					Stack("")
			}
			destConf.Detached = true
			ltsvlog.Logger.Info().String("msg", "detached destination").
				Stringer("srvIP", service.Address).
				Uint16("srvPort", service.Port).
				Stringer("destIP", destination.Address).
				Uint16("destPort", destination.Port).
				Uint16("cfgWeight", destConf.Weight).Log()
		}
	}
	return nil
}

func (l *LoadBalancer) changeWeight(ctx context.Context, srvIP net.IP, srvPort uint16, destIP net.IP, destPort uint16, weight uint16, lock bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	err := l.loadIPVS()
	if err != nil {
		return err
	}

	destKey := destinationKey(srvIP, srvPort, destIP, destPort)
	dest := l.servicesAndDests.findDestination(destKey)
	if dest == nil {
		return ltsvlog.Err(errors.New("no destination found")).
			Stringer("srvIP", srvIP).Uint16("srvPort", srvPort).
			Stringer("destIP", destIP).Uint16("destPort", destPort).Stack("")
	}
	service := dest.service
	destination := dest.destination
	destConf := l.config.findDestination(destKey)
	if destConf == nil {
		return ltsvlog.Err(errors.New("no destination config found")).
			Stringer("srvIP", srvIP).Uint16("srvPort", srvPort).
			Stringer("destIP", destIP).Uint16("destPort", destPort).Stack("")
	}

	destination.Weight = uint32(weight)
	err = l.ipvs.UpdateDestination(service, destination)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("faild to change ipvs destination weight, err=%s", err)
		}).Stringer("srvIP", srvIP).Uint16("srvPort", srvPort).
			Stringer("destIP", destIP).Uint16("destPort", destPort).
			Uint16("weight", weight).Stack("")
	}
	destConf.Weight = weight
	destConf.Locked = lock
	ltsvlog.Logger.Info().String("msg", "changed destination weight").
		Stringer("srvIP", srvIP).Uint16("srvPort", srvPort).
		Stringer("destIP", destIP).Uint16("destPort", destPort).
		Uint16("weight", weight).Bool("lock", lock).Log()
	return nil
}

func (l *LoadBalancer) doUpdateCheckers(ctx context.Context, config *Config) {
	for _, serviceConf := range config.Services {
		for _, destConf := range serviceConf.Destinations {
			c := destConf.HealthCheck
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "doUpdateCheckers").Stringer("destAddr", net.IP(destConf.Address)).Uint16("destPort", destConf.Port).Log()
			}
			destKey := destinationKey(net.IP(serviceConf.Address), serviceConf.Port, net.IP(destConf.Address), destConf.Port)
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

type ipvsServiceAndDestsByIPAndPort []*ipvsServiceAndDests

func (a ipvsServiceAndDestsByIPAndPort) Len() int      { return len(a) }
func (a ipvsServiceAndDestsByIPAndPort) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ipvsServiceAndDestsByIPAndPort) Less(i, j int) bool {
	si := a[i].service
	sj := a[j].service
	c := bytes.Compare(si.Address, sj.Address)
	if c < 0 {
		return true
	} else if c > 0 {
		return false
	} else {
		return si.Port < sj.Port
	}
}

type ipvsDestinationsByIPAndPort []*ipvsDestination

func (a ipvsDestinationsByIPAndPort) Len() int      { return len(a) }
func (a ipvsDestinationsByIPAndPort) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ipvsDestinationsByIPAndPort) Less(i, j int) bool {
	di := a[i].destination
	dj := a[j].destination
	c := bytes.Compare(di.Address, dj.Address)
	if c < 0 {
		return true
	} else if c > 0 {
		return false
	} else {
		return di.Port < dj.Port
	}
}
