// mdns-demo: Zero-config mDNS service announcer and discovery monitor.
//
// Run it, and it just works:
//  1. Registers a service on this machine (service type, instance name, port)
//  2. Browses for all other instances of the same service type on the LAN
//  3. Prints every discovery event with timestamps — new arrivals, departures
//  4. Periodically prints a summary table of all known peers
//  5. On Ctrl-C: sends goodbye, prints final summary
//
// Multiple instances on the same machine are fully supported — each gets a
// unique hostname and instance name automatically.
//
// Usage:
//
//	./mdns-demo                              # use defaults
//	./mdns-demo -name "Alice"                # custom instance name
//	./mdns-demo -service _http._tcp -port 80 # custom service type + port
//	./mdns-demo -log                         # verbose mDNS protocol logging
//
// Copy the binary to another machine on the same LAN and run it too —
// both instances will discover each other within seconds.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mdns "mdns"
)

func main() {
	// --- Parse flags (all optional, sensible defaults) ---
	instanceName := flag.String("name", "", "Instance name (default: hostname-PID)")
	serviceType := flag.String("service", "_mdns-demo._tcp", "Service type (e.g. _http._tcp)")
	svcPort := flag.Int("port", 9999, "Service port to advertise")
	mdnsPort := flag.Int("mdns-port", mdns.DefaultPort, "mDNS UDP port")
	hostName := flag.String("host", "", "mDNS hostname (default: auto-unique)")
	enableIPv6 := flag.Bool("ipv6", false, "Enable IPv6 multicast")
	verbose := flag.Bool("log", false, "Verbose mDNS protocol logging")
	summaryEvery := flag.Int("summary", 15, "Print summary table every N seconds (0=off)")
	flag.Usage = printUsage
	flag.Parse()

	// --- Derive unique hostname and instance name for same-machine support ---
	pid := os.Getpid()
	if *hostName == "" {
		// Auto-generate a unique hostname: system-hostname + "-<pid>".
		sysHost, _ := os.Hostname()
		if sysHost == "" {
			sysHost = "mdns-node"
		}
		// Sanitize: replace dots and spaces with dashes.
		sysHost = strings.NewReplacer(".", "-", " ", "-").Replace(sysHost)
		*hostName = fmt.Sprintf("%s-%d", sysHost, pid)
	}
	if *instanceName == "" {
		// Auto-generate a unique instance name.
		sysHost, _ := os.Hostname()
		if sysHost == "" {
			sysHost = "Node"
		}
		*instanceName = fmt.Sprintf("%s-%d", sysHost, pid)
	}

	// --- Banner ---
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║                    mDNS Demo (RFC 6762)                     ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// --- Create and start mDNS server ---
	cfg := mdns.DefaultConfig()
	cfg.Port = *mdnsPort
	cfg.EnableIPv6 = *enableIPv6
	cfg.HostName = *hostName
	if *verbose {
		cfg.LogFunc = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "  [debug] %s\n", fmt.Sprintf(format, args...))
		}
	}

	srv, err := mdns.NewServer(cfg)
	mustNoErr(err)
	mustNoErr(srv.Start())
	defer srv.Close()

	// Wait for host record probing to complete (RFC 6762 §8.1).
	time.Sleep(500 * time.Millisecond)

	// Print our own info.
	hostIPs := srv.HostIPs()
	v4Count, v6Count := countIPVersions(hostIPs)
	fmt.Printf("  ┌─ This node ──────────────────────────────────────────────────\n")
	fmt.Printf("  │  Hostname:   %s\n", srv.HostName())
	fmt.Printf("  │  Instance:   %s\n", *instanceName)
	fmt.Printf("  │  Addresses:  %d IPv4, %d IPv6", v4Count, v6Count)
	if v4Count > 0 {
		var v4s []string
		for _, ip := range hostIPs {
			if ip.To4() != nil {
				v4s = append(v4s, ip.String())
			}
		}
		fmt.Printf("  [%s]", strings.Join(v4s, ", "))
	}
	fmt.Println()
	fmt.Printf("  │  mDNS port:  %d\n", *mdnsPort)
	fmt.Printf("  │  PID:        %d\n", pid)
	fmt.Printf("  └──────────────────────────────────────────────────────────────\n")
	fmt.Println()

	// --- Register our service ---
	svc := &mdns.ServiceInstance{
		Name: *instanceName,
		Type: *serviceType,
		Port: uint16(*svcPort),
		Text: []string{
			fmt.Sprintf("started=%d", time.Now().Unix()),
			fmt.Sprintf("pid=%d", pid),
			"platform=mdns-demo",
		},
	}
	mustNoErr(srv.RegisterService(svc))

	fmt.Printf("  ┌─ Advertising service ────────────────────────────────────────\n")
	fmt.Printf("  │  Instance:   %s\n", *instanceName)
	fmt.Printf("  │  Type:       %s\n", *serviceType)
	fmt.Printf("  │  Port:       %d\n", *svcPort)
	fmt.Printf("  │  Probing:    3 probes x 250ms (RFC 6762 §8.1)\n")
	fmt.Printf("  │  Announcing: double-announce (RFC 6762 §8.3)\n")
	fmt.Printf("  │  Goodbye:    will send on exit (RFC 6762 §10.1)\n")
	fmt.Printf("  └──────────────────────────────────────────────────────────────\n")
	fmt.Println()

	// --- Start browsing for the same service type ---
	browser, err := srv.Browse(*serviceType)
	mustNoErr(err)
	events, err := browser.Start()
	mustNoErr(err)
	defer browser.Stop()

	fmt.Printf("  ┌─ Discovery ──────────────────────────────────────────────────\n")
	fmt.Printf("  │  Browsing:   %s\n", *serviceType)
	fmt.Printf("  │  Backoff:    1s then 2s, 4s, ... 1h max (RFC 6762 §5.2)\n")
	fmt.Printf("  │  Features:  Known-Answer Suppression, Cache Maintenance,\n")
	fmt.Printf("  │             Passive Observation, IPv4-priority\n")
	fmt.Printf("  └──────────────────────────────────────────────────────────────\n")
	fmt.Println()
	fmt.Println("  Waiting for peers...  (Ctrl-C to stop)")
	fmt.Println("  ───────────────────────────────────────────────────────────────")
	fmt.Println()

	// --- Event loop ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var summaryTicker <-chan time.Time
	if *summaryEvery > 0 {
		summaryTicker = time.After(time.Duration(*summaryEvery) * time.Second)
	}

	discoveryCount := 0
	startTime := time.Now()
	// Track our own hostname to filter self-discovery.
	// Each instance gets a unique hostname (hostname-PID.local.).
	myHost := srv.HostName()

	isSelf := func(info *mdns.ServiceInstanceInfo) bool {
		return info.Host == myHost
	}

	for {
		select {
		case ev := <-events:
			if isSelf(ev.Instance) {
				continue // skip self-discovery
			}
			now := time.Now().Format("15:04:05")
			switch ev.Action {
			case mdns.EventAdd:
				discoveryCount++
				printPeerFound(now, ev.Instance)
			case mdns.EventRemove:
				printPeerLost(now, ev.Instance)
			}

		case <-summaryTicker:
			printSummaryFiltered(browser, startTime, isSelf)
			summaryTicker = time.After(time.Duration(*summaryEvery) * time.Second)

		case <-sig:
			fmt.Println()
			fmt.Println("  ───────────────────────────────────────────────────────────────")
			fmt.Println()
			printSummaryFiltered(browser, startTime, isSelf)
			fmt.Println()
			fmt.Printf("  Total peers discovered: %d\n", discoveryCount)
			fmt.Printf("  Uptime:                 %s\n", formatDuration(time.Since(startTime)))
			fmt.Println()
			fmt.Println("  Sending goodbye packets (TTL=0)...  RFC 6762 §10.1")
			fmt.Println("  Done.")
			return
		}
	}
}

// --- printing helpers ---

func printPeerFound(ts string, s *mdns.ServiceInstanceInfo) {
	ipStrs := formatIPs(s.IPs)

	fmt.Printf("  [%s]  + %-30s  ONLINE\n", ts, s.Name)
	fmt.Printf("           type     = %s\n", s.Type)
	fmt.Printf("           host     = %s\n", s.Host)
	fmt.Printf("           port     = %d\n", s.Port)
	fmt.Printf("           addrs    = %s\n", strings.Join(ipStrs, ", "))
	if len(s.Text) > 0 {
		fmt.Printf("           txt      = %s\n", strings.Join(s.Text, ", "))
	}
	fmt.Printf("           srv prio = %d  weight = %d\n", s.Priority, s.Weight)
	fmt.Println()
}

func printPeerLost(ts string, s *mdns.ServiceInstanceInfo) {
	fmt.Printf("  [%s]  - %-30s  OFFLINE\n", ts, s.Name)
	fmt.Printf("           host     = %s\n", s.Host)
	fmt.Println()
}

func printSummary(browser *mdns.Browser, startTime time.Time) {
	printSummaryFiltered(browser, startTime, nil)
}

func printSummaryFiltered(browser *mdns.Browser, startTime time.Time, skip func(*mdns.ServiceInstanceInfo) bool) {
	all := browser.Instances()
	var instances []*mdns.ServiceInstanceInfo
	for _, s := range all {
		if skip != nil && skip(s) {
			continue
		}
		instances = append(instances, s)
	}
	now := time.Now().Format("15:04:05")
	uptime := formatDuration(time.Since(startTime))

	fmt.Printf("  [%s]  ┄┄┄ SUMMARY (%s, %d peer%s) ┄┄┄┄\n",
		now, uptime, len(instances), plural(len(instances)))

	if len(instances) == 0 {
		fmt.Println("           (no peers yet)")
		fmt.Println()
		return
	}

	for _, s := range instances {
		ipStrs := formatIPs(s.IPs)
		fmt.Printf("  %-30s  %s:%d  [%s]\n",
			truncate(s.Name, 30),
			firstOr(ipStrs, "?"),
			s.Port,
			s.Host)
	}
	fmt.Println()
}

// --- utility ---

func countIPVersions(ips []net.IP) (int, int) {
	var v4, v6 int
	for _, ip := range ips {
		if ip.To4() != nil {
			v4++
		} else {
			v6++
		}
	}
	return v4, v6
}

func formatIPs(ips []net.IP) []string {
	var result []string
	for _, ip := range ips {
		if ip.To4() != nil {
			result = append(result, "v4:"+ip.String())
		} else {
			result = append(result, "v6:"+ip.String())
		}
	}
	return result
}

func firstOr(ss []string, def string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return def
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func mustNoErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  FATAL: %v\n\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `
mdns-demo — Zero-config mDNS service announcer + discovery monitor

Just run it. It registers a service and discovers peers on the LAN.
Copy to another machine and run again — they find each other.
Multiple instances on the SAME machine also work (unique hostname per PID).

Usage:
  mdns-demo [flags]

Flags:
  -name string        Instance name (default: hostname-PID)
  -service string     Service type, e.g. _http._tcp (default "_mdns-demo._tcp")
  -port int           Service port to advertise (default 9999)
  -mdns-port int      mDNS UDP port — shared by all instances (default 53533)
  -host string        mDNS hostname (default: auto-unique hostname-PID)
  -ipv6               Enable IPv6 multicast
  -log                Verbose mDNS protocol logging
  -summary int        Print summary table every N seconds (default 15, 0=off)

Examples:
  mdns-demo                                # simplest: just run it
  mdns-demo -name "My Laptop"              # custom name
  mdns-demo -service _http._tcp -port 80   # advertise an HTTP service
  mdns-demo -log                           # debug mode

Same machine, multiple terminals:
  Terminal 1:  mdns-demo
  Terminal 2:  mdns-demo
  Terminal 3:  mdns-demo -service _airplay._tcp

All three will discover each other automatically.

`)
}
