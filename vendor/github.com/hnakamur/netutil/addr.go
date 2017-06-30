// +build linux

package netutil

import (
	"net"
	"syscall"
	"unsafe"
)

// AddAddr adds the specified IP address to the interface.
func AddAddr(intf *net.Interface, ip net.IP, ipNet *net.IPNet, label string) error {
	return addOrDelAddr(intf.Index, syscall.RTM_NEWADDR, ip, ipNet, label,
		syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
}

// DelAddr deletes the specified IP address from the interface.
func DelAddr(intf *net.Interface, ip net.IP, ipNet *net.IPNet) error {
	return addOrDelAddr(intf.Index, syscall.RTM_DELADDR, ip, ipNet, "",
		syscall.NLM_F_ACK)
}

func buildAddOrDelAddrReq(ifIndex int, proto uint16, ip net.IP, ipNet *net.IPNet, label string, flags uint16) ([]byte, error) {
	ipAddr := ip.To4()
	isIPv4 := ipAddr != nil
	if !isIPv4 {
		ipAddr = ip.To16()
	}

	reqLen := syscall.SizeofNlMsghdr + syscall.SizeofIfAddrmsg +
		2*(syscall.SizeofRtAttr+len(ipAddr))
	var labelPaddedLen int
	if label != "" {
		labelPaddedLen = alignNlAttr(len(label) + 1)
		reqLen += syscall.SizeofRtAttr + labelPaddedLen
	}
	req := make([]byte, reqLen)
	p := req

	hdr := &syscall.NlMsghdr{
		Len:   uint32(reqLen),
		Type:  proto,
		Flags: syscall.NLM_F_REQUEST | flags,
		Seq:   1,
	}
	serializeNlMsghdr(p, hdr)
	p = p[syscall.SizeofNlMsghdr:]

	msg := new(syscall.IfAddrmsg)
	if isIPv4 {
		msg.Family = syscall.AF_INET
	} else {
		msg.Family = syscall.AF_INET6
	}
	prefixlen, _ := ipNet.Mask.Size()
	msg.Prefixlen = uint8(prefixlen)
	msg.Index = uint32(ifIndex)
	serializeIfAddrmsg(p, msg)
	p = p[syscall.SizeofIfAddrmsg:]

	attr := &syscall.RtAttr{
		Len:  syscall.SizeofRtAttr + uint16(len(ipAddr)),
		Type: syscall.IFA_LOCAL,
	}
	serializeRtAttr(p, attr, []byte(ipAddr))
	p = p[attr.Len:]

	attr = &syscall.RtAttr{
		Len:  syscall.SizeofRtAttr + uint16(len(ipAddr)),
		Type: syscall.IFA_ADDRESS,
	}
	serializeRtAttr(p, attr, []byte(ipAddr))
	p = p[attr.Len:]

	if label != "" {
		attr = &syscall.RtAttr{
			Len:  syscall.SizeofRtAttr + uint16(labelPaddedLen),
			Type: syscall.IFA_LABEL,
		}
		serializeRtAttr(p, attr, []byte(label), []byte{'\x00'})
	}

	return req, nil
}

func addOrDelAddr(ifIndex int, proto uint16, ip net.IP, ipNet *net.IPNet, label string, flags uint16) error {
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(s)
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(s, lsa); err != nil {
		return err
	}
	req, err := buildAddOrDelAddrReq(ifIndex, proto, ip, ipNet, label, flags)
	if err != nil {
		return err
	}

	if err := syscall.Sendto(s, req, 0, lsa); err != nil {
		return err
	}
	rb := make([]byte, syscall.Getpagesize())
done:
	for {
		nr, _, err := syscall.Recvfrom(s, rb, 0)
		if err != nil {
			return err
		}
		if nr < syscall.NLMSG_HDRLEN {
			return syscall.EINVAL
		}
		msgs, err := syscall.ParseNetlinkMessage(rb[:nr])
		if err != nil {
			return err
		}
		for _, msg := range msgs {
			if msg.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if msg.Header.Type == syscall.NLMSG_ERROR {
				errCode := *(*int32)(unsafe.Pointer(&msg.Data[:4][0]))
				if errCode == 0 {
					break done
				}
				return syscall.Errno(-errCode)
			}
		}
	}
	return nil
}

func serializeNlMsghdr(b []byte, hdr *syscall.NlMsghdr) {
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = hdr.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = hdr.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = hdr.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = hdr.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = hdr.Pid
}

func serializeIfAddrmsg(b []byte, msg *syscall.IfAddrmsg) {
	*(*uint8)(unsafe.Pointer(&b[0])) = msg.Family
	*(*uint8)(unsafe.Pointer(&b[1])) = msg.Prefixlen
	*(*uint8)(unsafe.Pointer(&b[2])) = msg.Flags
	*(*uint8)(unsafe.Pointer(&b[3])) = msg.Scope
	*(*uint32)(unsafe.Pointer(&b[4:8][0])) = msg.Index
}

func serializeRtAttr(b []byte, attr *syscall.RtAttr, data ...[]byte) {
	*(*uint16)(unsafe.Pointer(&b[0:2][0])) = attr.Len
	*(*uint16)(unsafe.Pointer(&b[2:4][0])) = attr.Type
	p := b[4:]
	for _, d := range data {
		copy(p, d)
		p = p[len(d):]
	}
}

func align(size, tick int) int {
	return (size + tick - 1) &^ (tick - 1)
}

func alignNlMsg(size int) int {
	return align(size, syscall.NLMSG_ALIGNTO)
}

func alignNlAttr(size int) int {
	return align(size, syscall.NLA_ALIGNTO)
}
