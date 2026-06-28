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

## Logging and Warnings

The library never writes to the terminal directly. All output is delivered
through two optional callbacks in `Config`:

### LogFunc — debug logging

```go
cfg := mdns.DefaultConfig()
cfg.LogFunc = func(format string, args ...any) {
    log.Printf("[mdns] "+format, args...)
}
```

### WarningFunc — health alerts

`WarningFunc` is called when the library detects a non-fatal issue that may
affect functionality. The most common warning is `multicast_route_broken`,
fired when the system's multicast route is corrupted (typically by a VPN).

```go
cfg := mdns.DefaultConfig()
cfg.WarningFunc = func(w mdns.Warning) {
    switch w.Code {
    case "multicast_route_broken":
        log.Printf("[mdns] WARNING: %s (%s)", w.Message, w.Hint)
    }
}
```

If `WarningFunc` is nil, warnings fall back to `LogFunc`. If both are nil,
the library is completely silent.

### Integration with popular logging frameworks

```go
// slog (Go 1.21+)
cfg.LogFunc = func(format string, args ...any) {
    slog.Debug(fmt.Sprintf(format, args...))
}
cfg.WarningFunc = func(w mdns.Warning) {
    slog.Warn(w.Message, "code", w.Code, "hint", w.Hint)
}

// zap
cfg.LogFunc = func(format string, args ...any) {
    logger.Debug(fmt.Sprintf(format, args...))
}
cfg.WarningFunc = func(w mdns.Warning) {
    logger.Warn(w.Message, zap.String("code", w.Code), zap.String("hint", w.Hint))
}

// logrus
cfg.LogFunc = func(format string, args ...any) {
    logrus.Debugf(format, args...)
}
cfg.WarningFunc = func(w mdns.Warning) {
    logrus.WithField("code", w.Code).Warn(w.Message)
}
```

### Manual health check

You can also check multicast route health before starting a server:

```go
if err := mdns.CheckMulticastRoute(); err != nil {
    log.Printf("mDNS will not work: %v", err)
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

## Troubleshooting

### `sendto: no route to host` on multicast send

mDNS sends UDP packets to `224.0.0.251` (IPv4 multicast). If the OS multicast
route is missing or corrupted, all sends fail with this error.

**Quick diagnosis:**

```bash
# Check for the 224.0.0.0/4 multicast route
netstat -rn | grep 224

# Healthy output looks like:
#   224.0.0/4          link#12            UmCS                  en1
#   224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en1

# If you see a "!" flag, the route is REJECT (broken):
#   224.0.0/4          link#12            UmCS                  en1      !
```

**Common causes and fixes:**

| Cause | How to fix |
|---|---|
| **VPN / network extension** (sing-box, Tailscale, Clash, WireGuard, etc.) installed a `RTF_REJECT` route over `224.0.0.0/4` | Disconnect or quit the VPN client. If the route persists after disconnect, reboot. |
| **Missing multicast route** (some minimal Linux setups, Docker-only hosts) | `sudo route add -net 224.0.0.0/4 dev eth0` (Linux) or `sudo route add -net 224.0.0.0/4 -interface en0` (macOS) |
| **Firewall blocking multicast** (pf, iptables, Windows Firewall, Little Snitch) | Allow outbound UDP to `224.0.0.0/4` on port 5353. On macOS: `sudo pfctl -d` temporarily to test. |
| **Wrong interface selected** (machine has Docker / VM bridge adapters) | Pass `Config{Interfaces: []string{"en0"}}` to use a specific interface. |
| **No active network interface** (Wi-Fi off, cable unplugged) | Connect to a network first. mDNS only works on active local links. |

**macOS-specific: VPN network extensions corrupting multicast routes**

VPN clients that use the NetworkExtension framework (sing-box, Tailscale,
Clash with TUN mode, etc.) can install a reject route on `224.0.0.0/4` that
persists even after the VPN is disconnected. This is a known macOS issue.

```bash
# Verify the reject flag
netstat -rn | grep "224.0.0/4"
# If you see "!" at the end, the route is rejected

# Fix option 1: Reboot (cleanest)
sudo reboot

# Fix option 2: Manually delete and re-add the route
sudo route delete 224.0.0.0/4
sudo route add -net 224.0.0.0/4 -interface en0
```

**Linux-specific: missing multicast route on headless / container hosts**

```bash
# Add persistent multicast route
sudo ip route add 224.0.0.0/4 dev eth0

# Verify
ip route show | grep 224
```

### Service not discovered by peers

- Ensure both machines are on the **same L2 network** (same switch / Wi-Fi).
  mDNS multicast does not cross subnets without an mDNS reflector (e.g. Avahi `reflector`).
- Check that **port 5353 UDP** is not blocked by a firewall on either machine.
- If using a custom port via `Config.Port`, all peers must use the same port.
- Run with `-log` flag (`./mdns-demo -log`) to see debug output.

### Multiple instances on the same machine

Each instance automatically generates a unique hostname (`hostname-<PID>`),
so running multiple `mdns-demo` processes in different terminals works
out of the box. They will discover each other via multicast loopback.

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
