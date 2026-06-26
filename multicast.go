package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Default IPv4 and IPv6 mDNS multicast addresses (RFC 6762 §3).
var (
	IPv4MulticastAddr = net.IPv4(224, 0, 0, 251)
	IPv6MulticastAddr = net.ParseIP("ff02::fb")
)

// PacketBufferSize is the max mDNS packet size (RFC 6762 §17 allows up to 9000,
// but the classic MTU-safe limit is 9000 for jumbo frames; we use 9000).
const PacketBufferSize = 9000

// ReceivedPacket holds a received UDP packet with its source address.
type ReceivedPacket struct {
	Data []byte
	From *net.UDPAddr
}

// MulticastConn wraps a pair of UDP sockets (IPv4 and optionally IPv6)
// for sending and receiving mDNS multicast traffic.
type MulticastConn struct {
	v4conn  *net.UDPConn
	v6conn  *net.UDPConn // may be nil if IPv6 is not enabled
	groupV4 *net.UDPAddr
	groupV6 *net.UDPAddr
	port    int

	packets chan ReceivedPacket // channel for incoming packets
	closed  atomic.Bool
	wg      sync.WaitGroup
}

// NewMulticastConn creates a multicast connection listening on the given port.
// It creates an IPv4 socket and optionally an IPv6 socket.
//
// If interfaces is non-empty, only the named interfaces are used for multicast
// group membership and outgoing traffic; otherwise all active multicast
// interfaces are used.
func NewMulticastConn(port int, enableIPv6 bool, interfaces []string) (*MulticastConn, error) {
	groupV4 := &net.UDPAddr{IP: IPv4MulticastAddr, Port: port}

	v4conn, err := listenMulticast("udp4", port)
	if err != nil {
		return nil, fmt.Errorf("mdns: failed to create IPv4 multicast socket: %w", err)
	}

	// Join multicast group on all active (optionally filtered) interfaces.
	if err := joinGroups(v4conn, IPv4MulticastAddr, interfaces); err != nil {
		v4conn.Close()
		return nil, fmt.Errorf("mdns: failed to join IPv4 multicast group: %w", err)
	}

	// Set the outgoing multicast interface (IP_MULTICAST_IF) only when the
	// caller has explicitly specified interfaces.  Without an explicit list
	// we leave the OS routing table in charge, which is the correct default
	// on macOS / Linux.  On Windows the user should specify Interfaces in
	// Config to avoid the default route selecting a virtual adapter
	// (Docker, Hyper-V, WSL2, VPN).
	if len(interfaces) > 0 {
		_ = setOutgoingInterface(v4conn, interfaces)
	}

	mc := &MulticastConn{
		v4conn:  v4conn,
		groupV4: groupV4,
		groupV6: &net.UDPAddr{IP: IPv6MulticastAddr, Port: port},
		port:    port,
		packets: make(chan ReceivedPacket, 256),
	}

	// Optionally set up IPv6.
	if enableIPv6 {
		v6conn, err := listenMulticast("udp6", port)
		if err == nil {
			if err := joinGroupsV6(v6conn, IPv6MulticastAddr, interfaces); err == nil {
				mc.v6conn = v6conn
			} else {
				v6conn.Close()
			}
		}
		// IPv6 failure is non-fatal.
	}

	// Start receive goroutines.
	mc.wg.Add(1)
	go mc.recvLoop(mc.v4conn)
	if mc.v6conn != nil {
		mc.wg.Add(1)
		go mc.recvLoop(mc.v6conn)
	}

	return mc, nil
}

// listenMulticast creates a UDP socket bound to 0.0.0.0:port (or [::]:port)
// with SO_REUSEADDR and multicast socket options applied.
func listenMulticast(network string, port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{}
	addr := ":" + fmt.Sprint(port)
	if network == "udp6" {
		addr = "[::]:" + fmt.Sprint(port)
	}

	// Apply platform-specific socket options before bind via Control.
	lc.Control = func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = applyMulticastOptions(fd, network)
		})
		if err != nil {
			return err
		}
		return serr
	}

	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// recvLoop reads packets from conn and forwards them to the packets channel.
func (mc *MulticastConn) recvLoop(conn *net.UDPConn) {
	defer mc.wg.Done()
	buf := make([]byte, PacketBufferSize)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if mc.closed.Load() {
				return
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case mc.packets <- ReceivedPacket{Data: pkt, From: src}:
		default:
			// Drop packet if buffer is full.
		}
	}
}

// Packets returns the channel for received packets.
func (mc *MulticastConn) Packets() <-chan ReceivedPacket {
	return mc.packets
}

// WriteMulticastV4 sends data to the IPv4 multicast group.
func (mc *MulticastConn) WriteMulticastV4(data []byte) (int, error) {
	return mc.v4conn.WriteToUDP(data, mc.groupV4)
}

// WriteMulticastV6 sends data to the IPv6 multicast group.
func (mc *MulticastConn) WriteMulticastV6(data []byte) (int, error) {
	if mc.v6conn == nil {
		return 0, errors.New("mdns: IPv6 not enabled")
	}
	return mc.v6conn.WriteToUDP(data, mc.groupV6)
}

// WriteMulticast sends to all enabled multicast groups.
func (mc *MulticastConn) WriteMulticast(data []byte) error {
	if _, err := mc.WriteMulticastV4(data); err != nil {
		return err
	}
	if mc.v6conn != nil {
		_, _ = mc.WriteMulticastV6(data)
	}
	return nil
}

// WriteTo sends data to a specific unicast address.
func (mc *MulticastConn) WriteTo(data []byte, addr *net.UDPAddr) (int, error) {
	if addr.IP.To4() != nil {
		return mc.v4conn.WriteToUDP(data, addr)
	}
	if mc.v6conn != nil {
		return mc.v6conn.WriteToUDP(data, addr)
	}
	return mc.v4conn.WriteToUDP(data, addr)
}

// Port returns the configured mDNS port.
func (mc *MulticastConn) Port() int { return mc.port }

// Close shuts down all sockets and goroutines.
func (mc *MulticastConn) Close() error {
	if mc.closed.Swap(true) {
		return nil
	}
	if mc.v4conn != nil {
		mc.v4conn.Close()
	}
	if mc.v6conn != nil {
		mc.v6conn.Close()
	}
	mc.wg.Wait()
	close(mc.packets)
	return nil
}

// activeMulticastInterfacesFor returns active, multicast-capable interfaces.
// If names is non-empty, only interfaces whose Name is in names are returned.
func activeMulticastInterfacesFor(names []string) []net.Interface {
	var result []net.Interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		if len(nameSet) > 0 && !nameSet[iface.Name] {
			continue
		}
		result = append(result, iface)
	}
	return result
}

// setOutgoingInterface sets IP_MULTICAST_IF to the best interface.
// This is critical on Windows where the default route may select a virtual
// adapter (Docker, Hyper-V, WSL2, VPN) instead of the physical LAN adapter.
//
// Interface selection priority:
//  1. If interfaces is non-empty, use the first matching one.
//  2. Otherwise, prefer the default-route interface (detected via a UDP "dial"
//     to a public address — no actual packets are sent).
//  3. Fall back to the first non-loopback IPv4 on an active multicast interface.
func setOutgoingInterface(conn *net.UDPConn, interfaces []string) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	// If explicit interfaces are configured, use the first one with an IPv4 addr.
	if len(interfaces) > 0 {
		for _, iface := range activeMulticastInterfacesFor(interfaces) {
			if ip4 := firstIPv4(iface); ip4 != nil {
				var serr error
				rawConn.Control(func(fd uintptr) {
					serr = setOutgoingInterfaceV4(fd, ip4)
				})
				return serr
			}
		}
	}

	// Auto-detect: prefer the default-route interface.
	if ip4 := defaultRouteIPv4(); ip4 != nil {
		var serr error
		rawConn.Control(func(fd uintptr) {
			serr = setOutgoingInterfaceV4(fd, ip4)
		})
		return serr
	}

	// Fallback: first non-loopback IPv4 from any active multicast interface.
	for _, iface := range activeMulticastInterfacesFor(nil) {
		if ip4 := firstIPv4(iface); ip4 != nil && !ip4.IsLoopback() {
			var serr error
			rawConn.Control(func(fd uintptr) {
				serr = setOutgoingInterfaceV4(fd, ip4)
			})
			return serr
		}
	}
	return nil
}

// firstIPv4 returns the first non-loopback IPv4 address on the interface.
func firstIPv4(iface net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil && !ip4.IsLoopback() {
			return ip4
		}
	}
	return nil
}

// defaultRouteIPv4 detects the IPv4 address of the default-route interface
// by opening a UDP "connection" to a public address. No packets are actually
// sent — Dial just sets up the socket and lets the kernel pick the source
// address based on the routing table.
func defaultRouteIPv4() net.IP {
	// Use a non-routable documentation address (RFC 5737) — the kernel
	// still uses it for route lookup but no packets will ever be sent
	// because we never Write on this socket.
	conn, err := net.DialTimeout("udp4", "203.0.113.1:80", 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr == nil {
		return nil
	}
	return localAddr.IP.To4()
}

// joinGroups joins the IPv4 multicast group on all active (optionally filtered) interfaces.
func joinGroups(conn *net.UDPConn, group net.IP, interfaces []string) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var lastErr error
	joined := false
	for _, iface := range activeMulticastInterfacesFor(interfaces) {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			var jerr error
			rawConn.Control(func(fd uintptr) {
				jerr = joinMulticastGroupV4(fd, group, ip4)
			})
			if jerr != nil {
				lastErr = jerr
			} else {
				joined = true
			}
		}
	}
	if !joined && lastErr != nil {
		return lastErr
	}
	return nil
}

// joinGroupsV6 joins the IPv6 multicast group on all active (optionally filtered) interfaces.
func joinGroupsV6(conn *net.UDPConn, group net.IP, interfaces []string) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var lastErr error
	joined := false
	for _, iface := range activeMulticastInterfacesFor(interfaces) {
		var jerr error
		rawConn.Control(func(fd uintptr) {
			jerr = joinMulticastGroupV6(fd, group, iface.Index)
		})
		if jerr != nil {
			lastErr = jerr
		} else {
			joined = true
		}
	}
	if !joined && lastErr != nil {
		return lastErr
	}
	return nil
}
