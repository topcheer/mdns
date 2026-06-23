# mdns-demo

Comprehensive mDNS (RFC 6762) demonstration tool. Demonstrates ALL protocol features.

## Quick Start

### Terminal 1: Register a service
```bash
# macOS
./mdns-demo-darwin-arm64 register -service "_demo._tcp" -instance "My Service" -svc-port 8080 -log

# Linux
./mdns-demo-linux-amd64 register -service "_demo._tcp" -instance "My Service" -svc-port 8080 -log

# Windows
mdns-demo-windows-amd64.exe register -service "_demo._tcp" -instance "My Service" -svc-port 8080 -log
```

### Terminal 2: Browse for services
```bash
./mdns-demo-darwin-arm64 browse -service "_demo._tcp" -log
```

### Terminal 2 (alternative): Interactive daemon
```bash
./mdns-demo-darwin-arm64 daemon -service "_demo._tcp" -instance "Daemon" -svc-port 9090 -log
```

## Commands

| Command | Description | Demonstrates |
|---|---|---|
| `register` | Register a service | Probing (§8.1), Announcing (§8.3), Goodbye (§10.1), Rate limiting (§6) |
| `browse` | Discover services | Exponential backoff (§5.2), Known-answer suppression (§7.1), Cache maintenance (§5.2) |
| `resolve` | Resolve hostname | One-shot query (§5.1), Host A/AAAA records, Reverse mapping (§4) |
| `enumerate` | List all service types | DNS-SD enumeration (RFC 6763) |
| `daemon` | All-in-one interactive | All features + live register/unregister/browse/resolve |

## Daemon Interactive Commands

```
mdns> reg _http._tcp "Web Server" 80 path=/,version=2.0
mdns> find _http._tcp
mdns> resolve webserver.local.
mdns> list
mdns> cache
mdns> stats
mdns> quit
```

## Features Demonstrated

### register command
- RFC 6762 §8.1: Probing (3 probes × 250ms + random delay)
- RFC 6762 §8.2: Conflict detection + tiebreaking (lexicographic rdata comparison)
- RFC 6762 §9: Conflict resolution (automatic rename on loss)
- RFC 6762 §8.3: Announcing (double announcement)
- RFC 6762 §10.1: Goodbye (TTL=0 on shutdown)
- RFC 6762 §6: Multicast rate limiting (1s per record)

### browse command
- RFC 6762 §5.2: Exponential backoff (1s → 2s → 4s → ... → 1h max)
- RFC 6762 §7.1: Known-answer suppression (includes known PTR records in query)
- RFC 6762 §7.2: TC bit multipacket (splits large known-answer sets)
- RFC 6762 §5.2: Cache maintenance queries (refreshes at 80% TTL)
- RFC 6762 §6.2: Additional records in PTR responses (SRV/TXT/A/AAAA)

### resolve command
- RFC 6762 §5.1: One-shot multicast query
- RFC 6762 §4: Reverse address mapping (in-addr.arpa.)
- RFC 6762 §6.1: NSEC negative responses (if type doesn't exist)

### All commands
- RFC 6762 §18.14: Packet validation (opcode/rcode checks)
- RFC 6762 §11: Source address verification
- RFC 6762 §6.7: Legacy unicast query support
- RFC 6762 §18.12: mDNS ID=0 enforcement
- RFC 6762 §6: Response timing (unique=10ms, shared=20-120ms random)
- RFC 6762 §10.2: Cache-flush bit handling
- RFC 6762 §10.5: Passive observation of failures
