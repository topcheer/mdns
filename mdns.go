package mdns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// LookupHost resolves a hostname (e.g. "myhost.local.") to IP addresses
// using a one-shot mDNS query. It blocks until at least one address is found
// or the context is cancelled.
//
// This is a convenience method that creates a temporary Server if needed.
// For repeated queries, use a persistent Server instance.
func LookupHost(ctx context.Context, host string, port int) ([]net.IP, error) {
	if port == 0 {
		port = DefaultPort
	}

	cfg := DefaultConfig()
	cfg.Port = port
	cfg.HostName = "" // don't advertise

	srv, err := NewServer(cfg)
	if err != nil {
		return nil, err
	}
	if err := srv.Start(); err != nil {
		return nil, err
	}
	defer srv.Close()

	return srv.ResolveHost(ctx, host)
}

// ResolveHost resolves a hostname using the running server's cache and network.
// IPv4 addresses are returned first, then IPv6 (if enabled).
func (s *Server) ResolveHost(ctx context.Context, host string) ([]net.IP, error) {
	hostName := normalizeName(host)

	// Check cache first.
	aRecords := s.cache.Lookup(rrKey(hostName, TypeA))
	aaaaRecords := s.cache.Lookup(rrKey(hostName, TypeAAAA))
	var ips []net.IP
	for _, rr := range aRecords {
		ips = append(ips, rr.IP)
	}
	for _, rr := range aaaaRecords {
		ips = append(ips, rr.IP)
	}
	if len(ips) > 0 {
		return sortIPsIPv4First(ips), nil
	}

	// Send a one-shot query (RFC 6762 §5.1).
	// BUG-1 fix: One-shot queries MUST set the QU bit (class | 0x8000) to
	// request unicast responses, which is more efficient for one-shot lookups.
	query := &Message{
		Header: Header{QDCount: 2},
		Questions: []*Question{
			{Name: hostName, Type: TypeA, Class: ClassIN | cacheFlushBit},
			{Name: hostName, Type: TypeAAAA, Class: ClassIN | cacheFlushBit},
		},
	}
	data, err := query.Pack()
	if err != nil {
		return nil, err
	}
	if err := s.conn.WriteMulticast(data); err != nil {
		return nil, err
	}

	// Poll cache for a response.
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(ips) > 0 {
				return sortIPsIPv4First(ips), nil
			}
			return nil, ctx.Err()
		case <-ticker.C:
			aRecords = s.cache.Lookup(rrKey(hostName, TypeA))
			aaaaRecords = s.cache.Lookup(rrKey(hostName, TypeAAAA))
			for _, rr := range aRecords {
				ips = append(ips, rr.IP)
			}
			for _, rr := range aaaaRecords {
				ips = append(ips, rr.IP)
			}
			if len(ips) > 0 {
				return sortIPsIPv4First(ips), nil
			}
		}
	}
}

// LookupService discovers service instances of the given type.
// It blocks until the context is cancelled or the timeout expires.
func LookupService(ctx context.Context, serviceType string, port int) ([]*ServiceInstanceInfo, error) {
	if port == 0 {
		port = DefaultPort
	}

	cfg := DefaultConfig()
	cfg.Port = port

	srv, err := NewServer(cfg)
	if err != nil {
		return nil, err
	}
	if err := srv.Start(); err != nil {
		return nil, err
	}
	defer srv.Close()

	browser, err := srv.Browse(serviceType)
	if err != nil {
		return nil, err
	}
	events, err := browser.Start()
	if err != nil {
		return nil, err
	}
	defer browser.Stop()

	// Wait for discovery results.
	for {
		select {
		case <-ctx.Done():
			return browser.Instances(), nil
		case ev, ok := <-events:
			if !ok {
				return browser.Instances(), nil
			}
			_ = ev
		}
	}
}

// String returns a debug string for the server state.
func (s *Server) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("mdns.Server{port=%d, hostname=%s, services=%d, browsers=%d}",
		s.config.Port, s.config.HostName, len(s.services), len(s.browsers))
}

// sortIPsIPv4First sorts a slice of IP addresses, putting IPv4 addresses
// before IPv6 addresses. Within each group, addresses are sorted by byte value.
// This implements the "IPv4 preferred" policy for service advertisement.
func sortIPsIPv4First(ips []net.IP) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	// Sort each group for deterministic output.
	sort.Slice(v4, func(i, j int) bool { return v4[i].String() < v4[j].String() })
	sort.Slice(v6, func(i, j int) bool { return v6[i].String() < v6[j].String() })
	return append(v4, v6...)
}
