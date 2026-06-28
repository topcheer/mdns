package mdns

import (
	"fmt"
	"net"
	"time"
)

// DefaultPort is the default mDNS port (RFC 6762 §6.1 uses 5353;
// configurable — the user requested 53533 as the default).
const DefaultPort = 53533

// DefaultDomain is the default mDNS domain.
const DefaultDomain = "local."

// DefaultTTL values from RFC 6762 §10.
const (
	DefaultHostTTL     = 120 * time.Second // A/AAAA/SRV records
	DefaultOtherTTL    = 75 * time.Second  // PTR/TXT records
	DefaultProbeWait   = 250 * time.Millisecond
	DefaultProbeCount  = 3
	DefaultAnnounceTTL = time.Second
)

// Config holds mDNS server configuration.
type Config struct {
	// Port is the UDP port to listen on. Default: 53533.
	Port int

	// Domain is the mDNS domain suffix. Default: "local.".
	Domain string

	// EnableIPv6 enables IPv6 multicast. Default: false.
	EnableIPv6 bool

	// HostName is the host name to advertise (e.g. "myhost").
	// If empty, the system hostname is used.
	HostName string

	// LogFunc is called for debug logging. If nil, no logging is done.
	LogFunc func(format string, args ...any)

	// WarningFunc is called when the server detects a non-fatal issue
	// that may affect functionality (e.g. broken multicast route caused
	// by a VPN). If nil, warnings are logged via LogFunc (if set).
	WarningFunc WarningFunc

	// Interfaces restricts which network interfaces to use.
	// If empty, all active multicast interfaces are used.
	Interfaces []string
}

// Warning describes a non-fatal issue detected by the mDNS server.
// Warnings are delivered via Config.WarningFunc.
type Warning struct {
	// Code is a machine-readable identifier for the warning.
	// Known codes:
	//   - "multicast_route_broken" — the system cannot send multicast packets
	//     (commonly caused by VPN network extensions corrupting the 224.0.0.0/4 route).
	Code string

	// Message is a human-readable description of the issue.
	Message string

	// Hint is a suggested action to resolve the issue.
	Hint string
}

// WarningFunc is a callback invoked when the server detects a non-fatal issue.
type WarningFunc func(Warning)

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:       DefaultPort,
		Domain:     DefaultDomain,
		EnableIPv6: false,
	}
}

// ServiceInstance describes a service to be registered or discovered.
type ServiceInstance struct {
	// Type is the service type, e.g. "_http._tcp".
	Type string

	// Name is the instance name, e.g. "My Web Server".
	Name string

	// Domain is the domain, e.g. "local.".
	Domain string

	// Host is the hostname, e.g. "myhost.local.".
	// If empty, the server's hostname is used.
	Host string

	// Port is the service port.
	Port uint16

	// IPs is the list of IP addresses for the service.
	// If empty, the server's local addresses are used.
	IPs []net.IP

	// Text is the TXT record data.
	Text []string

	// Priority is the SRV priority.
	Priority uint16

	// Weight is the SRV weight.
	Weight uint16

	// TTL override (0 = use defaults).
	TTL uint32
}

// ServiceType returns the full service type domain, e.g. "_http._tcp.local.".
func (s *ServiceInstance) ServiceType() string {
	return normalizeServiceType(s.Type) + "." + ensureDomain(s.Domain)
}

// InstanceName returns the full instance name, e.g. "My Web Server._http._tcp.local.".
func (s *ServiceInstance) InstanceName() string {
	return s.Name + "." + s.ServiceType()
}

// ServiceInstanceInfo contains discovered service instance details.
type ServiceInstanceInfo struct {
	Name     string   // instance name (e.g. "My Web Server")
	Type     string   // service type (e.g. "_http._tcp.local.")
	Domain   string   // domain (e.g. "local.")
	Host     string   // hostname (e.g. "myhost.local.")
	Port     uint16   // service port
	IPs      []net.IP // IP addresses
	Text     []string // TXT record data
	Priority uint16   // SRV priority
	Weight   uint16   // SRV weight
}

// String returns a human-readable description of the service instance.
func (s *ServiceInstanceInfo) String() string {
	ipStrs := make([]string, len(s.IPs))
	for i, ip := range s.IPs {
		ipStrs[i] = ip.String()
	}
	return fmt.Sprintf("%s [%s] host=%s port=%d ips=[%s]",
		s.Name, s.Type, s.Host, s.Port, fmt.Sprint(ipStrs))
}

// normalizeServiceType ensures the service type is in "_type._proto" format.
func normalizeServiceType(t string) string {
	return t
}

// ensureDomain ensures a trailing dot on the domain.
func ensureDomain(d string) string {
	if d == "" {
		return DefaultDomain
	}
	return normalizeName(d)
}
