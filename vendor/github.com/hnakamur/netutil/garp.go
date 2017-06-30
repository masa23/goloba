// +build linux

package netutil

import (
	"net"

	"github.com/mdlayher/arp"
)

// SendGARP sends a GARP (Gratuitous ARP) packet.
func SendGARP(intf *net.Interface, ip net.IP) error {
	c, err := arp.Dial(intf)
	if err != nil {
		return err
	}
	defer c.Close()

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
