package vrrp

import (
	"errors"
	"net"

	"github.com/mdlayher/arp"
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

// SendGarp sends a gratuitous ARP packet for the IP address.
//func SendGARP(ip net.IP) error {
//	intf, err := InterfaceByIP(ip)
//	if err != nil {
//		return err
//	}
//
//	c, err := arp.Dial(intf)
//	if err != nil {
//		return err
//	}
//	defer c.Close()
//
//	p, err := arp.NewPacket(arp.OperationRequest, intf.HardwareAddr, ip,
//		net.HardwareAddr{0, 0, 0, 0, 0, 0}, ip)
//	if err != nil {
//		return err
//	}
//	err = c.WriteTo(p, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
//	if err != nil {
//		return err
//	}
//	return nil
//}

func SendGARP(c *arp.Client, intf *net.Interface, ip net.IP) error {
	p, err := arp.NewPacket(arp.OperationRequest, intf.HardwareAddr, ip,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip)
	if err != nil {
		return err
	}
	err = c.WriteTo(p, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return err
	}
	return nil
}
