package netutil

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

func TestIPAndNet_Equal(t *testing.T) {
	testCases := []struct {
		s1, s2      string
		wantIsEqual bool
	}{
		{"192.168.0.1/32", "192.168.0.1/32", true},
		{"192.168.0.1/32", "192.168.0.1/31", false},
		{"192.168.0.1/32", "192.168.0.2/32", false},
	}
	for _, tc := range testCases {
		ipAndNet1, err := ParseCIDR(tc.s1)
		if err != nil {
			t.Fatalf("invalid CIDR in test pattern s1, %s", tc.s1)
		}
		ipAndNet2, err := ParseCIDR(tc.s2)
		if err != nil {
			t.Fatalf("invalid CIDR in test pattern s2, %s", tc.s2)
		}
		gotIsEqual := ipAndNet1.Equal(ipAndNet2)
		if gotIsEqual != tc.wantIsEqual {
			t.Errorf("s1=%s, s2=%s, gotIsEqual=%v, wantIsEqual=%v", tc.s1, tc.s2, gotIsEqual, tc.wantIsEqual)
		}
	}
}

func TestParseIP(t *testing.T) {
	testCases := []struct {
		addr   string
		wantIP net.IP
	}{
		{"192.168.0.1", net.IPv4(192, 168, 0, 1).To4()},
		{"192.168.0.1", net.ParseIP("192.168.0.1").To4()},
		{"192.168.0.999", nil},
		{"192.168.0.1/32", nil},
		{"", nil},
		{"foo", nil},
		{"fe80::fc54:ff:febb:e3f", net.ParseIP("fe80::fc54:ff:febb:e3f")},
		{"fe80::fc54:ff:febb::e3f", nil},
		{"fe80::fc54:ff:febb:e3f/32", nil},
	}

	for _, tc := range testCases {
		gotIP := ParseIP(tc.addr)
		if !bytes.Equal(gotIP, tc.wantIP) {
			t.Errorf("addr=%q, gotIP=%v, wantIP=%v", tc.addr, gotIP, tc.wantIP)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	testCases := []struct {
		cidr         string
		wantIPAndNet *IPAndNet
		wantErr      bool
	}{
		{
			cidr: "192.168.0.1/24",
			wantIPAndNet: &IPAndNet{
				IP:    ParseIP("192.168.0.1"),
				IPNet: &net.IPNet{IP: ParseIP("192.168.0.0"), Mask: net.CIDRMask(24, 32)},
			},
			wantErr: false,
		},
		{
			cidr: "192.168.0.2/24",
			wantIPAndNet: &IPAndNet{
				IP:    ParseIP("192.168.0.2"),
				IPNet: &net.IPNet{IP: ParseIP("192.168.0.0"), Mask: net.CIDRMask(24, 32)},
			},
			wantErr: false,
		},
		{
			cidr:         "192.168.0.999/24",
			wantIPAndNet: nil,
			wantErr:      true,
		},
		{
			cidr:         "",
			wantIPAndNet: nil,
			wantErr:      true,
		},
		{
			cidr:         "foo",
			wantIPAndNet: nil,
			wantErr:      true,
		},
		{
			cidr: "fe80::fc54:ff:febb:e3f/64",
			wantIPAndNet: &IPAndNet{
				IP:    ParseIP("fe80::fc54:ff:febb:e3f"),
				IPNet: &net.IPNet{IP: ParseIP("fe80::0"), Mask: net.CIDRMask(64, 128)},
			},
			wantErr: false,
		},
		{
			cidr:         "fe80::fc54:ff:febb:e3f",
			wantIPAndNet: nil,
			wantErr:      true,
		},
		{
			cidr:         "fe80::fc54:ff:febb::e3f/64",
			wantIPAndNet: nil,
			wantErr:      true,
		},
	}

	for _, tc := range testCases {
		gotIPAndNet, err := ParseCIDR(tc.cidr)
		if err != nil {
			if tc.wantErr {
				wantErrMsg := fmt.Sprintf("invalid CIDR address: %s", tc.cidr)
				if err.Error() != wantErrMsg {
					t.Errorf("cidr=%q, gotErrMsg=%s, wantErrMsg=%s", tc.cidr, err.Error(), wantErrMsg)
				}
			} else {
				t.Errorf("cidr=%q, got an error %v, want no error", err, tc.cidr)
			}
		} else {
			if tc.wantErr {
				t.Errorf("cidr=%q, got no error, want an error", tc.cidr)
			} else {
				if !gotIPAndNet.Equal(tc.wantIPAndNet) {
					t.Errorf("cidr=%q, gotIPAndNet=%+v, wantIPAndNet=%+v", tc.cidr, gotIPAndNet, tc.wantIPAndNet)
				}
			}
		}
	}
}

func TestIP_UnmarshalYAML(t *testing.T) {
	testCases := []struct {
		addr    string
		wantIP  net.IP
		wantErr bool
	}{
		{"192.168.0.1", net.IPv4(192, 168, 0, 1).To4(), false},
		{"192.168.0.1", net.ParseIP("192.168.0.1").To4(), false},
		{"192.168.0.999", nil, true},
		{"192.168.0.1/32", nil, true},
		{"", nil, false},
		{"foo", nil, true},
		{"fe80::fc54:ff:febb:e3f", net.ParseIP("fe80::fc54:ff:febb:e3f"), false},
		{"fe80::fc54:ff:febb::e3f", nil, true},
		{"fe80::fc54:ff:febb:e3f/32", nil, true},
	}

	type config struct {
		Addr IP `yaml:"addr"`
	}
	for _, tc := range testCases {
		data := []byte(fmt.Sprintf("addr: %s", tc.addr))
		var cfg config
		err := yaml.Unmarshal(data, &cfg)
		if err != nil {
			if tc.wantErr {
				wantErrMsg := fmt.Sprintf("unmarshal YAML error; invalid IP address: %s", tc.addr)
				if err.Error() != wantErrMsg {
					t.Errorf("got errMsg=%s, wantErrMsg=%s, address=%s", err.Error(), wantErrMsg, tc.addr)
				}
			} else {
				t.Errorf("got an error, wantErr=false, address=%s", tc.addr)
			}
		} else {
			if tc.wantErr {
				t.Errorf("got no error, wantErr=true, address=%s", tc.addr)
			} else {
				if !net.IP(cfg.Addr).Equal(tc.wantIP) {
					t.Errorf("gotIP=%v, wantIP=%v", cfg.Addr, tc.wantIP)
				} else if len(net.IP(cfg.Addr)) != len(tc.wantIP) {
					t.Errorf("gotIP=%v, gotIPLen=%d, wantIP=%v, wantIPLen=%d",
						cfg.Addr, len(net.IP(cfg.Addr)), tc.wantIP, len(tc.wantIP))
				}
			}
		}
	}
}

func TestIP_MarshalYAML(t *testing.T) {
	testCases := []struct {
		ip       net.IP
		wantYAML string
		wantErr  bool
	}{
		{net.IPv4(192, 168, 0, 1).To4(), "addr: 192.168.0.1\n", false},
		{net.ParseIP("fe80::fc54:ff:febb:e3f"), "addr: fe80::fc54:ff:febb:e3f\n", false},
	}

	type config struct {
		Addr IP `yaml:"addr"`
	}
	for _, tc := range testCases {
		cfg := &config{Addr: IP(tc.ip)}
		data, err := yaml.Marshal(&cfg)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("ip=%+v, got an error, want no error", tc.ip)
			}
		} else {
			if tc.wantErr {
				t.Errorf("ip=%+v, got no error, want an error", tc.ip)
			} else {
				gotYAML := string(data)
				if gotYAML != tc.wantYAML {
					t.Errorf("ip=%+v, gotYAML=%q, wantYAML=%q", tc.ip, gotYAML, tc.wantYAML)
				}
			}
		}
	}
}

func TestIPAndNet_MarshalYAML(t *testing.T) {
	testCases := []struct {
		ipAndNet *IPAndNet
		wantYAML string
		wantErr  bool
	}{
		{
			ipAndNet: &IPAndNet{
				IP:    ParseIP("192.168.0.1"),
				IPNet: &net.IPNet{IP: ParseIP("192.168.0.0"), Mask: net.CIDRMask(24, 32)},
			},
			wantYAML: "addr: 192.168.0.1/24\n",
			wantErr:  false,
		},
		{
			ipAndNet: &IPAndNet{
				IP:    ParseIP("fe80::fc54:ff:febb:e3f"),
				IPNet: &net.IPNet{IP: ParseIP("fe80::0"), Mask: net.CIDRMask(64, 128)},
			},
			wantYAML: "addr: fe80::fc54:ff:febb:e3f/64\n",
			wantErr:  false,
		},
		{
			ipAndNet: &IPAndNet{},
			wantYAML: "addr: null\n",
			wantErr:  false,
		},
	}

	type config struct {
		Addr *IPAndNet `yaml:"addr"`
	}
	for _, tc := range testCases {
		cfg := &config{Addr: tc.ipAndNet}
		data, err := yaml.Marshal(&cfg)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("ipAndNet=%+v, got an error, want no error", tc.ipAndNet)
			}
		} else {
			if tc.wantErr {
				t.Errorf("ipAndNet=%+v, got no error, want an error", tc.ipAndNet)
			} else {
				gotYAML := string(data)
				if gotYAML != tc.wantYAML {
					t.Errorf("ipAndNet=%+v, gotYAML=%q, wantYAML=%q", tc.ipAndNet, gotYAML, tc.wantYAML)
				}
			}
		}
	}
}

func TestIPAndNet_UnmarshalYAML(t *testing.T) {
	t.Run("pointer", func(t *testing.T) {
		testCases := []struct {
			cidr         string
			wantIPAndNet *IPAndNet
			wantErr      bool
		}{
			{
				cidr: "192.168.0.1/24",
				wantIPAndNet: &IPAndNet{
					IP:    ParseIP("192.168.0.1"),
					IPNet: &net.IPNet{IP: ParseIP("192.168.0.0"), Mask: net.CIDRMask(24, 32)},
				},
				wantErr: false,
			},
			{
				cidr: "192.168.0.2/24",
				wantIPAndNet: &IPAndNet{
					IP:    ParseIP("192.168.0.2"),
					IPNet: &net.IPNet{IP: ParseIP("192.168.0.0"), Mask: net.CIDRMask(24, 32)},
				},
				wantErr: false,
			},
			{
				cidr:         "192.168.0.999/24",
				wantIPAndNet: nil,
				wantErr:      true,
			},
			{
				cidr:         "",
				wantIPAndNet: nil,
				wantErr:      false, // UNmarshalYAML is not called for the empty cidr value.
			},
			{
				cidr:         "foo",
				wantIPAndNet: nil,
				wantErr:      true,
			},
			{
				cidr: "fe80::fc54:ff:febb:e3f/64",
				wantIPAndNet: &IPAndNet{
					IP:    ParseIP("fe80::fc54:ff:febb:e3f"),
					IPNet: &net.IPNet{IP: ParseIP("fe80::0"), Mask: net.CIDRMask(64, 128)},
				},
				wantErr: false,
			},
			{
				cidr:         "fe80::fc54:ff:febb:e3f",
				wantIPAndNet: nil,
				wantErr:      true,
			},
			{
				cidr:         "fe80::fc54:ff:febb::e3f/64",
				wantIPAndNet: nil,
				wantErr:      true,
			},
		}

		type config struct {
			IPAndNet *IPAndNet `yaml:"cidr"`
		}
		for _, tc := range testCases {
			data := []byte(fmt.Sprintf("cidr: %s", tc.cidr))
			var cfg config
			err := yaml.Unmarshal(data, &cfg)
			if err != nil {
				if tc.wantErr {
					wantErrMsg := fmt.Sprintf("unmarshal YAML error; invalid CIDR address: %s", tc.cidr)
					if err.Error() != wantErrMsg {
						t.Errorf("cidr=%s, gotErrMsg=%s, wantErrMsg=%s", tc.cidr, err.Error(), wantErrMsg)
					}
				} else {
					t.Errorf("cidr=%s, got an error, want no error", tc.cidr)
				}
			} else {
				if tc.wantErr {
					t.Errorf("cidr=%s, got no error, want an error", tc.cidr)
				} else {
					gotIPAndNet := cfg.IPAndNet
					if !gotIPAndNet.Equal(tc.wantIPAndNet) {
						t.Errorf("cidr=%q, gotIPAndNet=%+v, wantIPAndNet=%+v", tc.cidr, gotIPAndNet, tc.wantIPAndNet)
					}
				}
			}
		}
	})
	t.Run("value", func(t *testing.T) {
		testCases := []struct {
			cidr         string
			wantIPAndNet *IPAndNet
			wantErr      bool
		}{
			{
				cidr: "192.168.0.1/24",
				wantIPAndNet: &IPAndNet{
					IP:    ParseIP("192.168.0.1"),
					IPNet: &net.IPNet{IP: ParseIP("192.168.0.0"), Mask: net.CIDRMask(24, 32)},
				},
				wantErr: false,
			},
			{
				cidr: "192.168.0.2/24",
				wantIPAndNet: &IPAndNet{
					IP:    ParseIP("192.168.0.2"),
					IPNet: &net.IPNet{IP: ParseIP("192.168.0.0"), Mask: net.CIDRMask(24, 32)},
				},
				wantErr: false,
			},
			{
				cidr:         "192.168.0.999/24",
				wantIPAndNet: nil,
				wantErr:      true,
			},
			{
				cidr:         "",
				wantIPAndNet: &IPAndNet{},
				wantErr:      false, // UNmarshalYAML is not called for the empty cidr value.
			},
			{
				cidr:         "foo",
				wantIPAndNet: nil,
				wantErr:      true,
			},
			{
				cidr: "fe80::fc54:ff:febb:e3f/64",
				wantIPAndNet: &IPAndNet{
					IP:    ParseIP("fe80::fc54:ff:febb:e3f"),
					IPNet: &net.IPNet{IP: ParseIP("fe80::0"), Mask: net.CIDRMask(64, 128)},
				},
				wantErr: false,
			},
			{
				cidr:         "fe80::fc54:ff:febb:e3f",
				wantIPAndNet: nil,
				wantErr:      true,
			},
			{
				cidr:         "fe80::fc54:ff:febb::e3f/64",
				wantIPAndNet: nil,
				wantErr:      true,
			},
		}

		type config struct {
			IPAndNet IPAndNet `yaml:"cidr"`
		}
		for _, tc := range testCases {
			data := []byte(fmt.Sprintf("cidr: %s", tc.cidr))
			var cfg config
			err := yaml.Unmarshal(data, &cfg)
			if err != nil {
				if tc.wantErr {
					wantErrMsg := fmt.Sprintf("unmarshal YAML error; invalid CIDR address: %s", tc.cidr)
					if err.Error() != wantErrMsg {
						t.Errorf("cidr=%s, gotErrMsg=%s, wantErrMsg=%s", tc.cidr, err.Error(), wantErrMsg)
					}
				} else {
					t.Errorf("cidr=%s, got an error, want no error", tc.cidr)
				}
			} else {
				if tc.wantErr {
					t.Errorf("cidr=%s, got no error, want an error", tc.cidr)
				} else {
					gotIPAndNet := cfg.IPAndNet
					if !gotIPAndNet.Equal(tc.wantIPAndNet) {
						t.Errorf("cidr=%q, gotIPAndNet=%+v, wantIPAndNet=%+v", tc.cidr, gotIPAndNet, tc.wantIPAndNet)
					}
				}
			}
		}
	})
}
