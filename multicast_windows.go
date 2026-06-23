//go:build windows

package mdns

import (
	"fmt"
	"net"
	"syscall"
)

// Windows multicast socket option constants (from winsock2.h / ws2ipdef.h).
// These are not defined in Go's syscall package for Windows.
const (
	winIP_MULTICAST_TTL   = 10
	winIP_MULTICAST_LOOP  = 11
	winIP_ADD_MEMBERSHIP  = 12
	winIPV6_MULTICAST_HOPS = 10 // IPV6_MULTICAST_HOPS
	winIPV6_MULTICAST_LOOP = 11 // IPV6_MULTICAST_LOOP
	winIPV6_ADD_MEMBERSHIP = 12 // IPV6_JOIN_GROUP
)

// applyMulticastOptions sets socket options needed for mDNS on Windows.
func applyMulticastOptions(fd uintptr, network string) error {
	// SO_REUSEADDR (on Windows, this is similar to BSD's SO_REUSEPORT).
	if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("mdns: SO_REUSEADDR: %w", err)
	}

	if network == "udp4" {
		// IP_MULTICAST_TTL = 255.
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, winIP_MULTICAST_TTL, 255); err != nil {
			return fmt.Errorf("mdns: IP_MULTICAST_TTL: %w", err)
		}
		// IP_MULTICAST_LOOP = 1.
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, winIP_MULTICAST_LOOP, 1); err != nil {
			return fmt.Errorf("mdns: IP_MULTICAST_LOOP: %w", err)
		}
	} else if network == "udp6" {
		// IPV6_MULTICAST_HOPS = 255.
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, winIPV6_MULTICAST_HOPS, 255); err != nil {
			return fmt.Errorf("mdns: IPV6_MULTICAST_HOPS: %w", err)
		}
		// IPV6_MULTICAST_LOOP = 1.
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, winIPV6_MULTICAST_LOOP, 1); err != nil {
			return fmt.Errorf("mdns: IPV6_MULTICAST_LOOP: %w", err)
		}
	}

	return nil
}

// joinMulticastGroupV4 joins the IPv4 multicast group on the given interface IP.
func joinMulticastGroupV4(fd uintptr, group, ifaceIP net.IP) error {
	g4 := group.To4()
	if g4 == nil {
		return fmt.Errorf("mdns: not an IPv4 address: %s", group)
	}
	i4 := ifaceIP.To4()
	if i4 == nil {
		return fmt.Errorf("mdns: not an IPv4 interface address: %s", ifaceIP)
	}
	mreq := syscall.IPMreq{
		Multiaddr: [4]byte{g4[0], g4[1], g4[2], g4[3]},
		Interface: [4]byte{i4[0], i4[1], i4[2], i4[3]},
	}
	return syscall.SetsockoptIPMreq(syscall.Handle(fd), syscall.IPPROTO_IP, winIP_ADD_MEMBERSHIP, &mreq)
}

// joinMulticastGroupV6 joins the IPv6 multicast group on the given interface index.
func joinMulticastGroupV6(fd uintptr, group net.IP, ifaceIndex int) error {
	g16 := group.To16()
	if g16 == nil {
		return fmt.Errorf("mdns: not an IPv6 address: %s", group)
	}
	mreq := syscall.IPv6Mreq{
		Multiaddr: [16]byte{
			g16[0], g16[1], g16[2], g16[3],
			g16[4], g16[5], g16[6], g16[7],
			g16[8], g16[9], g16[10], g16[11],
			g16[12], g16[13], g16[14], g16[15],
		},
		Interface: uint32(ifaceIndex),
	}
	return syscall.SetsockoptIPv6Mreq(syscall.Handle(fd), syscall.IPPROTO_IPV6, winIPV6_ADD_MEMBERSHIP, &mreq)
}
