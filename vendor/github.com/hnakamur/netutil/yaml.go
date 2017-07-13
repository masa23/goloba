package netutil

import (
	"bytes"
	"fmt"
	"net"
)

// IP is an IP address which can be marshaled and marshaled to YAML.
type IP net.IP

// IPAndNet is an IP address with IPNet which can be marshaled and marshaled to YAML.
type IPAndNet struct {
	IP    net.IP
	IPNet *net.IPNet
}

// UnmarshalYAML unmarshal an IP address string from YAML.
func (i *IP) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	ip := ParseIP(s)
	if ip == nil {
		return fmt.Errorf("unmarshal YAML error; invalid IP address: %s", s)
	}
	*i = IP(ip)
	return nil
}

// MarshalYAML marshal an IP address to string.
func (i IP) MarshalYAML() (interface{}, error) {
	if i == nil {
		return nil, nil
	} else {
		return net.IP(i).String(), nil
	}
}

// UnmarshalYAML unmarshal an CIDR address string from YAML.
func (i *IPAndNet) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	ipAndNet, err := ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("unmarshal YAML error; %v", err)
	}
	if ipAndNet != nil {
		*i = *ipAndNet
	}
	return nil
}

// MarshalYAML marshal an IP address and network to string.
func (i IPAndNet) MarshalYAML() (interface{}, error) {
	if i.IP == nil && i.IPNet == nil {
		return nil, nil
	} else {
		ipNet := net.IPNet{IP: i.IP, Mask: i.IPNet.Mask}
		return ipNet.String(), nil
	}
}

// ParseIP parses s as an IP address using net.ParseIP(),
// and converts the IP with IPTo4Ifv4().
func ParseIP(s string) net.IP {
	return IPTo4IfV4(net.ParseIP(s))
}

// ParseCIDR parses s as a CIDR using net.ParseCIDR(),
// and converts the IP with IPTo4Ifv4().
func ParseCIDR(s string) (*IPAndNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	if ip == nil && ipNet == nil {
		return nil, nil
	} else {
		return &IPAndNet{
			IP:    IPTo4IfV4(ip),
			IPNet: IPNetTo4IfV4(ipNet),
		}, nil
	}
}

// IPTo4IfV4 returns the ip.To4() if ip is a v4 address,
// returns ip otherwise.
func IPTo4IfV4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	ipv4 := ip.To4()
	if ipv4 != nil {
		return ipv4
	} else {
		return ip
	}
}

// IPNetTo4IfV4 returns the IP network with IP replaced with IPto4If4().
func IPNetTo4IfV4(ipNet *net.IPNet) *net.IPNet {
	if ipNet == nil {
		return nil
	}
	return &net.IPNet{
		IP:   IPTo4IfV4(ipNet.IP),
		Mask: ipNet.Mask,
	}
}

// Equal reports whether i and j are the same IP address and network.
// IP addresses are compared with IP.Equal and networks are compared
// with the results of IPNet.String().
func (i *IPAndNet) Equal(j *IPAndNet) bool {
	if i == nil {
		return j == nil
	} else {
		return j != nil && i.IP.Equal(j.IP) && IPNetEqual(i.IPNet, j.IPNet)
	}
}

// IPNetEqual resports whether ipNet1 and ipNet2 are the same IP network.
func IPNetEqual(ipNet1, ipNet2 *net.IPNet) bool {
	if ipNet1 == nil {
		return ipNet2 == nil
	} else {
		return ipNet2 != nil && ipNet1.IP.Equal(ipNet2.IP) && bytes.Equal(ipNet1.Mask, ipNet2.Mask)
	}
}
