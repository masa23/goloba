package vrrp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hnakamur/ltsvlog"
)

// Packet is a VRRP packet which has the following format.
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                    IPv4 Fields or IPv6 Fields                 |
//   ...                                                             ...
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |(rsvd) |     Max Adver Int     |          Checksum             |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    +                                                               +
//    |                       IPvX Address(es)                        |
//    +                                                               +
//    +                                                               +
//    +                                                               +
//    +                                                               +
//    |                                                               |
//    +                                                               +
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Packet struct {
	Version       uint8 // 4-bit field
	Type          uint8 // 4-bit field
	VirtualRtrID  uint8
	Priority      uint8
	CountIPvXAddr uint8
	Rsvd          uint8  // 4-bit field
	MaxAdverInt   uint16 // 12-bit field
	Checksum      uint16
	IPvXAddrs     []net.IP
}

const (
	Port                    = 112
	Version3                = 3
	PacketTypeAdvertisement = 1
	DefaultPriority         = 100
	DefaultMaxAdverInt      = time.Second
)

func (p *Packet) AppendTo(buf []byte) ([]byte, error) {
	if len(p.IPvXAddrs) != int(p.CountIPvXAddr) {
		return nil, ltsvlog.Err(errors.New("unmatch CountIPvXAddr and IPvXAddrs length")).
			Uint8("CountIPvXAddr", p.CountIPvXAddr).Int("IPvXAddrsLen", len(p.IPvXAddrs)).Stack("")
	}

	checksum := p.calcChecksum()
	if p.Checksum == 0 {
		p.Checksum = checksum
	} else if p.Checksum != checksum {
		return nil, ltsvlog.Err(errors.New("unmatch checksum")).
			Uint16("checksum", p.Checksum).Uint16("calculatedChecksum", checksum).Stack("")
	}

	buf = append(buf, byte((p.Version&0xf<<4)|p.Type&0xf), byte(p.VirtualRtrID),
		byte(p.Priority), byte(p.CountIPvXAddr),
		byte(uint16(p.Rsvd)<<4|p.MaxAdverInt>>8), byte(p.MaxAdverInt),
		byte(p.Checksum>>8), byte(p.Checksum))
	for _, addr := range p.IPvXAddrs {
		buf = append(buf, []byte(addr)...)
	}
	return buf, nil
}

func (p *Packet) WriteTo(w io.Writer) (int, error) {
	var buf [32]byte
	pbuf, err := p.AppendTo(buf[:])
	if err != nil {
		return 0, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("faile to write VRRP packet, err=%v", err)
		})
	}
	return w.Write(pbuf)
}

func (p *Packet) ReadV4From(r io.Reader) (int, error) {
	totalLen, err := p.readHeader(r)
	if err != nil {
		return 0, err
	}

	var buf [net.IPv4len]byte
	for i := uint8(0); i < p.CountIPvXAddr; i++ {
		n, err := io.ReadFull(r, buf[:])
		if err != nil {
			return 0, ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed read IPv4 addresses VRRP packet, err=%v", err)
			}).Uint8("i", i).Uint8("count", p.CountIPvXAddr).Stack("")
		}
		p.IPvXAddrs = append(p.IPvXAddrs, net.IP(buf[:]))
		totalLen += n
	}
	return totalLen, nil
}

func (p *Packet) ReadV6From(r io.Reader) (int, error) {
	totalLen, err := p.readHeader(r)
	if err != nil {
		return 0, err
	}

	var buf [net.IPv6len]byte
	for i := uint8(0); i < p.CountIPvXAddr; i++ {
		n, err := io.ReadFull(r, buf[:])
		if err != nil {
			return 0, ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("failed read IPv6 addresses VRRP packet, err=%v", err)
			}).Uint8("i", i).Uint8("count", p.CountIPvXAddr).Stack("")
		}
		p.IPvXAddrs = append(p.IPvXAddrs, net.IP(buf[:]))
		totalLen += n
	}
	return totalLen, nil
}

func (p *Packet) readHeader(r io.Reader) (int, error) {
	var buf [8]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed read VRRP packet, err=%v", err)
		}).Stack("")
	}
	p.Version = buf[0] >> 4
	p.Type = buf[0] & 0xf
	p.VirtualRtrID = buf[1]
	p.Priority = buf[2]
	p.CountIPvXAddr = buf[3]
	p.Rsvd = buf[4] >> 4
	p.MaxAdverInt = uint16(buf[4]&0x4)<<8 | uint16(buf[5])
	p.Checksum = uint16(buf[6])<<8 | uint16(buf[7])
	return len(buf), nil
}

func (p *Packet) calcChecksum() uint16 {
	return 0
}

func ToCentiSeconds(d time.Duration) uint16 {
	return uint16(d / time.Millisecond / 10)
}
