# mDNS - Go Multicast DNS (RFC 6762)

A complete from-scratch implementation of [Multicast DNS (RFC 6762)](https://datatracker.ietf.org/doc/html/rfc6762)
in Go, with no third-party mDNS library dependencies. Only the Go standard library is used.

## Features

- **Full DNS wire format** — name encoding/decoding with compression pointers, all common RR types
  (A, AAAA, PTR, SRV, TXT, NSEC, CNAME), message pack/unpack
- **Cross-platform multicast** — macOS, Linux, Windows (amd64 + arm64)
- **Service registration** with probing, announcing, and goodbye (RFC 6762 §8)
- **Service browsing** with PTR/SRV/TXT/A resolution and live add/remove events
- **Host resolution** via one-shot mDNS queries
- **Record cache** with TTL-based expiry and cache-flush semantics (§10)
- **Known-Answer Suppression** (§7.1) and response delay randomization (§6)
- **Legacy unicast query** support (§6.7)
- **Conflict detection** for registered records (§8.2)
- **DNS-SD service enumeration** via `_services._dns-sd._udp.local.`
- Configurable port (default: **53533**)

## Quick Start

### Register a service

```go
package main

import (
    "fmt"
    "mdns"
)

func main() {
    srv, _ := mdns.NewServer(mdns.DefaultConfig())
    srv.Start()
    defer srv.Close()

    srv.RegisterService(&mdns.ServiceInstance{
        Name: "My Web Server",
        Type: "_http._tcp",
        Port: 8080,
        Text: []string{"path=/", "version=1.0"},
    })

    // Server is now advertising on the network.
    select {} // block forever
}
```

### Browse for services

```go
srv, _ := mdns.NewServer(mdns.DefaultConfig())
srv.Start()
defer srv.Close()

browser, _ := srv.Browse("_http._tcp")
events, _ := browser.Start()
defer browser.Stop()

for ev := range events {
    switch ev.Action {
    case mdns.EventAdd:
        fmt.Printf("Found: %s\n", ev.Instance)
    case mdns.EventRemove:
        fmt.Printf("Lost: %s\n", ev.Instance)
    }
}
```

### Resolve a hostname

```go
ips, _ := srv.ResolveHost(ctx, "myhost.local.")
```

### Run the example app

```bash
# Register and browse simultaneously (two terminals)
go run ./cmd/mdns-example -mode register -name "MyService" -type "_test._tcp" -svc-port 8080
go run ./cmd/mdns-example -mode browse -type "_test._tcp"

# Resolve a hostname
go run ./cmd/mdns-example -mode resolve -resolve "myhost.local."
```

## Configuration

```go
config := mdns.Config{
    Port:      53533,           // configurable mDNS port (default 53533)
    Domain:    "local.",        // mDNS domain suffix
    EnableIPv6: true,           // enable IPv6 multicast
    HostName:  "myhost",        // hostname to advertise
    LogFunc:   func(f string, a ...any) { log.Printf(f, a...) },
}
```

## Architecture

```
mdns/
├── go.mod                  # Module definition
├── config.go               # Config, ServiceInstance, ServiceInstanceInfo types
├── dns_name.go             # DNS name encoding/decoding with compression
├── dns_rr.go               # Resource record types (A, AAAA, PTR, SRV, TXT, NSEC)
├── dns_message.go          # DNS message pack/unpack
├── multicast.go            # Cross-platform multicast connection (common)
├── multicast_unix.go       # macOS/Linux socket options (SO_REUSEADDR/PORT, TTL, loop)
├── multicast_windows.go    # Windows socket options
├── sockopts_darwin.go      # macOS SO_REUSEPORT constant
├── sockopts_linux.go       # Linux SO_REUSEPORT constant
├── sockopts_windows.go     # Windows no-op
├── cache.go                # Record cache with TTL expiry and cache-flush
├── server.go               # Core mDNS engine (query/response/probe/conflict)
├── service.go              # Service registration, probing, announcing
├── browser.go              # Service browsing and discovery
├── mdns.go                 # Public API (LookupHost, LookupService)
├── dns_test.go             # DNS wire format tests
├── cache_test.go           # Cache tests
├── integration_test.go     # Full mDNS protocol tests
└── cmd/mdns-example/       # Example CLI application
```

### Key Design Decisions

- **No third-party deps**: Only Go standard library (`net`, `syscall`, `encoding/binary`)
- **Platform-specific socket options** via build tags (`//go:build darwin`, `linux`, `windows`)
- **Thread-safe**: All shared state protected by mutexes, race-detector clean
- **Event-driven**: Browser events delivered via channels for easy integration

## RFC 6762 Compliance

| Feature | Section | Status |
|---|---|---|
| Multicast Address & Port | §3, §6.1 | IPv4 + IPv6, configurable port |
| Probing | §8.1 | 3 probes × 250ms + random delay |
| Simultaneous Probe Tiebreaking | §8.2 | Conflict detection |
| Announcing | §8.3 | Double-announce after probe |
| Goodbye | §10.1 | TTL=0 goodbye packets |
| Cache-Flush Bit | §10.2 | Flushes stale records |
| Known-Answer Suppression | §7.1 | Suppresses redundant responses |
| Response Delay | §6 | Random 20-120ms delay |
| Legacy Unicast Queries | §6.7 | Immediate unicast response |
| Additional Records | §6.2 | SRV/TXT/A in PTR responses |
| DNS-SD Enumeration | RFC 6763 | `_services._dns-sd._udp` PTR |

## Testing

```bash
# Unit tests
go test -short ./...

# Full test suite (includes multicast integration tests)
go test -race ./...

# Cross-platform compilation check
GOOS=darwin go build ./...
GOOS=linux go build ./...
GOOS=windows go build ./...
```

## License

MIT
