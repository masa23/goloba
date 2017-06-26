package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/hnakamur/ltsvlog"
	"github.com/mqliang/libipvs"
)

type ServicesAndDests struct {
	services map[string]*ServiceAndDests
}

type ServiceAndDests struct {
	service *libipvs.Service
	dests   map[string]*Dest
}

type Dest struct {
	dest     *libipvs.Destination
	detached bool
}

func main() {
	h, err := libipvs.New()
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create libipvs handler, err=%v", err)
		}).Stack(""))
	}

	servicesAndDests, err := ListServicesAndDests(h)
	if err != nil {
		ltsvlog.Logger.Err(err)
	}
	for sa, service := range servicesAndDests.services {
		ltsvlog.Logger.Info().String("sa", sa).Sprintf("service", "%+v", service.service).Log()
		for da, dest := range service.dests {
			ltsvlog.Logger.Info().String("da", da).Sprintf("dest", "%+v", dest.dest).Log()
		}
	}
}

func joinIPAndPort(ip net.IP, port uint16) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func ListServicesAndDests(h libipvs.IPVSHandle) (*ServicesAndDests, error) {
	servicesAndDests := &ServicesAndDests{services: make(map[string]*ServiceAndDests)}

	services, err := h.ListServices()
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to list ipvs services, err=%v", err)
		}).Stack("")
	}
	for _, service := range services {
		serviceAndDests := &ServiceAndDests{
			service: service,
			dests:   make(map[string]*Dest),
		}
		serviceKey := joinIPAndPort(service.Address, service.Port)
		servicesAndDests.services[serviceKey] = serviceAndDests

		dests, err := h.ListDestinations(service)
		if err != nil {
			return nil, ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to list ipvs destinations, err=%v", err)
			}).Stringer("serviceAddress", service.Address).Stack("")
		}

		for _, dest := range dests {
			destKey := joinIPAndPort(dest.Address, dest.Port)
			serviceAndDests.dests[destKey] = &Dest{dest: dest}
		}
	}
	return servicesAndDests, nil
}

func run() error {
	ipvs, err := libipvs.New()
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to create libipvs handler, err=%v", err)
		}).Stack("")
	}

	services, err := ipvs.ListServices()
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to list ipvs services, err=%v", err)
		}).Stack("")
	}

	for i, service := range services {
		ltsvlog.Logger.Info().Int("i", i).Sprintf("service", "%+v", service).Log()
		dests, err := ipvs.ListDestinations(service)
		if err != nil {
			return ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed to list ipvs destinations, err=%v", err)
			}).Stack("")
		}
		for j, dest := range dests {
			ltsvlog.Logger.Info().Int("i", i).Int("j", j).Sprintf("dest", "%+v", dest).Log()
		}
	}
	return nil
}
