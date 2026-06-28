package mdns

import (
	"fmt"
	"net"
	"strings"
)

// CheckMulticastRoute tests whether the system can send multicast packets
// to the standard mDNS IPv4 multicast address (224.0.0.251).
//
// It creates a temporary UDP socket, sets IP_MULTICAST_IF to the best
// detected LAN interface, and attempts to write a single byte. If the
// send fails — most commonly with "no route to host" — the multicast
// route is broken.
//
// Common causes:
//   - VPN network extensions (sing-box, Tailscale, Clash TUN mode) installing
//     an RTF_REJECT route on 224.0.0.0/4 (macOS)
//   - Missing multicast route on headless / container hosts (Linux)
//   - Firewall blocking outbound multicast
//
// Returns nil if the send succeeds, or an error describing the failure.
//
// This function is safe to call before starting a Server. It is also
// called automatically during Server.Start().
func CheckMulticastRoute() error {
	// Create a temporary UDP socket.
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("mdns: cannot create UDP socket: %w", err)
	}
	defer conn.Close()

	// Try to set the outgoing multicast interface.
	if ip := defaultRouteIPv4(); ip != nil {
		if rawConn, serr := conn.SyscallConn(); serr == nil {
			rawConn.Control(func(fd uintptr) {
				_ = setOutgoingInterfaceV4(fd, ip)
			})
		}
	}

	// Attempt to send a single byte to the multicast group.
	_, err = conn.WriteToUDP([]byte{0}, &net.UDPAddr{
		IP:   IPv4MulticastAddr,
		Port: DefaultPort,
	})
	if err != nil {
		// Check if this is the "no route to host" error.
		errStr := err.Error()
		if strings.Contains(errStr, "no route to host") ||
			strings.Contains(errStr, "network is unreachable") {
			return fmt.Errorf("mdns: multicast route is broken or missing: %w", err)
		}
		return fmt.Errorf("mdns: failed to send multicast test packet: %w", err)
	}

	return nil
}
