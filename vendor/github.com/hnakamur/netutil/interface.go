package netutil

import (
	"errors"
	"net"
)

// InterfaceByIP return the interface matched by the IP address.
func InterfaceByIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, intf := range interfaces {
		addrs, err := intf.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			i, _, err := net.ParseCIDR(a.String())
			if err != nil {
				return nil, err
			}
			if i.Equal(ip) {
				return &intf, nil
			}
		}
	}
	return nil, errors.New("interface not found")
}

// HasAddr returns whether or not the interface has the specified IP address.
func HasAddr(intf *net.Interface, ip net.IP) (bool, error) {
	addrs, err := intf.Addrs()
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		i, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return false, err
		}
		if i.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}
