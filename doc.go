// Package mdns implements Multicast DNS (mDNS) as specified in RFC 6762,
// providing zero-configuration service discovery on local networks.
//
// This is a from-scratch implementation with no third-party dependencies —
// only the Go standard library is used.
//
// # Quick Start
//
// Register a service and discover peers:
//
//	srv, _ := mdns.NewServer(mdns.DefaultConfig())
//	srv.Start()
//	defer srv.Close()
//
//	// Advertise a service
//	srv.RegisterService(&mdns.ServiceInstance{
//	    Name: "My Printer",
//	    Type: "_ipp._tcp",
//	    Port: 631,
//	})
//
//	// Browse for services
//	browser, _ := srv.Browse("_ipp._tcp")
//	events, _ := browser.Start()
//	defer browser.Stop()
//
//	for ev := range events {
//	    if ev.Action == mdns.EventAdd {
//	        fmt.Printf("Found: %s on %s:%d\n",
//	            ev.Instance.Name, ev.Instance.Host, ev.Instance.Port)
//	    }
//	}
//
// # Key Types
//
//   - [Server]    — the core mDNS engine; create with [NewServer]
//   - [Config]    — server configuration; use [DefaultConfig] for defaults
//   - [ServiceInstance] — a service to register via [Server.RegisterService]
//   - [Browser]   — service discovery via [Server.Browse]
//   - [ServiceInstanceInfo] — resolved service details delivered via events
//
// # RFC 6762 Compliance
//
// This implementation covers all core sections of RFC 6762:
//
//   - Probing (§8.1) with simultaneous probe tiebreaking (§8.2)
//   - Conflict resolution with auto-rename (§9)
//   - Announcing — double-announce after probe (§8.3)
//   - Goodbye — TTL=0 on shutdown (§10.1)
//   - Cache-flush bit semantics (§10.2)
//   - Known-Answer Suppression with TTL check (§7.1)
//   - TC bit multipacket queries (§7.2)
//   - Exponential backoff browsing (§5.2)
//   - Cache maintenance queries at 80% TTL (§5.2)
//   - One-shot queries with QU bit (§5.1, §5.4)
//   - NSEC negative responses (§6.1)
//   - Reverse address mapping IPv4+IPv6 (§4)
//   - Passive observation of failures (§10.5)
//   - Source address verification (§11)
//   - Legacy unicast query support (§6.7)
//   - Multicast rate limiting (§6)
//   - Packet validation opcode/rcode (§18.14)
//   - DNS-SD service enumeration (RFC 6763)
//
// IPv4 addresses are prioritized for service advertisement.
// Multiple instances on the same machine are fully supported.
//
// # Cross-Platform Support
//
// Builds for macOS (amd64/arm64), Linux (amd64/arm64), and Windows (amd64/arm64).
package mdns
