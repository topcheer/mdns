# mdns — Go Multicast DNS (RFC 6762)

[![Go Reference](https://pkg.go.dev/badge/github.com/topcheer/mdns.svg)](https://pkg.go.dev/github.com/topcheer/mdns)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8)
![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![Created by](https://img.shields.io/badge/created%20by-ggcode-purple)](https://github.com/topcheer/ggcode)

A complete from-scratch implementation of [Multicast DNS (RFC 6762)](https://datatracker.ietf.org/doc/html/rfc6762) in Go. No third-party mDNS libraries — only the Go standard library.

## Install

```bash
go get github.com/topcheer/mdns
```

## Quick Start

### Register a service

```go
package main

import (
    "fmt"
    "github.com/topcheer/mdns"
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

    fmt.Println("Service registered. Press Ctrl-C to stop.")
    select {}
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
        fmt.Printf("Found: %s at %s:%d\n",
            ev.Instance.Name, ev.Instance.Host, ev.Instance.Port)
    case mdns.EventRemove:
        fmt.Printf("Lost: %s\n", ev.Instance.Name)
    }
}
```

### Resolve a hostname

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

ips, _ := srv.ResolveHost(ctx, "myhost.local.")
for _, ip := range ips {
    fmt.Println(ip)
}
```

### One-shot lookup (no persistent server)

```go
// Resolve a hostname without managing a Server
ips, _ := mdns.LookupHost(ctx, "myhost.local.", 0)

// Discover services without managing a Server
instances, _ := mdns.LookupService(ctx, "_http._tcp", 0)
```

## Configuration

```go
config := mdns.Config{
    Port:       mdns.DefaultPort,  // 53533 (configurable)
    Domain:     "local.",          // mDNS domain suffix
    EnableIPv6: false,             // enable IPv6 multicast
    HostName:   "myhost",          // empty = system hostname
    LogFunc:    func(f string, a ...any) { log.Printf(f, a...) },
}
```

## API Reference

### Core Types

| Type | Description |
|---|---|
| [`Server`](https://pkg.go.dev/github.com/topcheer/mdns#Server) | Core mDNS engine. Create with `NewServer()`. |
| [`Config`](https://pkg.go.dev/github.com/topcheer/mdns#Config) | Server configuration. Use `DefaultConfig()` for defaults. |
| [`ServiceInstance`](https://pkg.go.dev/github.com/topcheer/mdns#ServiceInstance) | Service to register via `Server.RegisterService()`. |
| [`Browser`](https://pkg.go.dev/github.com/topcheer/mdns#Browser) | Service discovery via `Server.Browse()`. |
| [`ServiceInstanceInfo`](https://pkg.go.dev/github.com/topcheer/mdns#ServiceInstanceInfo) | Resolved service details (name, host, port, IPs, TXT). |
| [`ServiceEvent`](https://pkg.go.dev/github.com/topcheer/mdns#ServiceEvent) | Event delivered to Browser subscribers. |

### Key Methods

| Method | Description |
|---|---|
| `NewServer(Config)` | Create a new mDNS server |
| `Server.Start()` | Begin listening and background tasks |
| `Server.RegisterService(*ServiceInstance)` | Register + probe + announce a service |
| `Server.UnregisterService(*ServiceInstance)` | Unregister + send goodbye |
| `Server.Browse(serviceType)` | Create a service browser |
| `Server.ResolveHost(ctx, host)` | Resolve hostname to IP addresses |
| `Browser.Start()` | Begin browsing, returns event channel |
| `Browser.Stop()` | Stop browsing |
| `Browser.Instances()` | Get all currently known instances |
| `Server.Cache()` | Access the record cache |
| `Server.HostIPs()` | Get this host's IP addresses |
| `LookupHost(ctx, host, port)` | One-shot hostname resolution |
| `LookupService(ctx, type, port)` | One-shot service discovery |

## RFC 6762 Compliance

| Feature | Section | Status |
|---|---|---|
| `.local.` domain, multicast addresses 224.0.0.251 / FF02::FB | §3 | ✅ |
| One-Shot query with QU bit (unicast response) | §5.1, §5.4 | ✅ |
| Exponential backoff browsing (1s → 2s → ... → 1h) | §5.2 | ✅ |
| Cache maintenance queries at 80% TTL | §5.2 | ✅ |
| Reverse address mapping (IPv4 `.in-addr.arpa.` + IPv6 `.ip6.arpa.`) | §4 | ✅ |
| Unique record immediate response (<10ms) | §6 | ✅ |
| Shared record random response delay (20–120ms) | §6 | ✅ |
| NSEC negative responses | §6.1 | ✅ |
| Additional records in PTR responses (SRV/TXT/A) | §6.2 | ✅ |
| Multicast rate limiting (1s per record) | §6 | ✅ |
| Legacy unicast query support | §6.7 | ✅ |
| Known-Answer Suppression with TTL ≥50% check | §7.1 | ✅ |
| TC bit multipacket known-answer | §7.2 | ✅ |
| Probing (3 × 250ms + random delay) | §8.1 | ✅ |
| Simultaneous probe tiebreaking (lexicographic rdata) | §8.2 | ✅ |
| Hostname A/AAAA probing | §8.1 | ✅ |
| Announcing (double-announce) | §8.3 | ✅ |
| Conflict resolution with auto-rename | §9 | ✅ |
| Goodbye (TTL=0) | §10.1 | ✅ |
| Cache-flush bit | §10.2 | ✅ |
| Passive observation of failures | §10.5 | ✅ |
| Source address verification (local subnet) | §11 | ✅ |
| Packet validation (opcode=0, rcode=0) | §18.14 | ✅ |
| DNS-SD service enumeration (`_services._dns-sd._udp`) | RFC 6763 | ✅ |

### Design Choices

- **IPv4 priority**: Service advertisement always puts IPv4 addresses first.
- **Same-machine multi-instance**: Each instance auto-generates a unique hostname.
- **Configurable port**: Default 53533 (standard mDNS uses 5353).

## Demo Application

The `cmd/mdns-demo` binary is a zero-config tool that registers a service and discovers peers:

```bash
# Build
go build -o mdns-demo ./cmd/mdns-demo

# Run (just works — registers + browses automatically)
./mdns-demo

# Custom service
./mdns-demo -service _http._tcp -port 8080 -name "My Server"

# Verbose logging
./mdns-demo -log
```

Run on multiple terminals or machines — they discover each other automatically.

Pre-built binaries for all platforms are in [Releases](../../releases).

## Architecture

```
mdns/
├── doc.go                  # Package documentation
├── config.go               # Config, ServiceInstance, ServiceInstanceInfo
├── dns_name.go             # DNS name encoding/decoding (RFC 1035 compression)
├── dns_rr.go               # Resource records: A, AAAA, PTR, SRV, TXT, NSEC
├── dns_message.go          # DNS message pack/unpack
├── multicast.go            # Cross-platform multicast connection
├── multicast_unix.go       # macOS/Linux socket setup
├── multicast_windows.go    # Windows socket setup
├── sockopts_{darwin,linux,windows}.go  # Platform SO_REUSEPORT
├── cache.go                # Record cache with TTL + cache-flush
├── server.go               # Core engine: query/response/probe/conflict
├── service.go              # Registration: probing, announcing, goodbye
├── browser.go              # Discovery: browse, backoff, known-answer, maintenance
├── mdns.go                 # Public API: NewServer, LookupHost, LookupService
├── *_test.go               # Unit + integration tests (24 tests)
└── cmd/mdns-demo/          # Zero-config demo application
```

## Testing

```bash
# Unit + integration tests with race detector
go test -race ./...

# Run with verbose output
go test -v -race ./...
```

All 24 tests pass with the `-race` flag enabled.

## Cross-Platform Compilation

```bash
GOOS=darwin  GOARCH=arm64 go build -o mdns-demo-darwin-arm64  ./cmd/mdns-demo
GOOS=darwin  GOARCH=amd64 go build -o mdns-demo-darwin-amd64  ./cmd/mdns-demo
GOOS=linux   GOARCH=amd64 go build -o mdns-demo-linux-amd64   ./cmd/mdns-demo
GOOS=linux   GOARCH=arm64 go build -o mdns-demo-linux-arm64   ./cmd/mdns-demo
GOOS=windows GOARCH=amd64 go build -o mdns-demo-windows-amd64 ./cmd/mdns-demo
GOOS=windows GOARCH=arm64 go build -o mdns-demo-windows-arm64 ./cmd/mdns-demo
```

## License

[MIT](LICENSE)
