package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mdns"
)

func main() {
	mode := flag.String("mode", "both", "Mode: register, browse, both, resolve")
	serviceType := flag.String("type", "_test._tcp", "Service type (e.g. _http._tcp)")
	serviceName := flag.String("name", "TestService", "Service instance name")
	port := flag.Int("port", 0, "mDNS port (default 53533)")
	svcPort := flag.Int("svc-port", 8080, "Port the service listens on")
	resolveHost := flag.String("resolve", "", "Hostname to resolve (e.g. myhost.local.)")
	flag.Parse()

	if *port == 0 {
		*port = mdns.DefaultPort
	}

	cfg := mdns.DefaultConfig()
	cfg.Port = *port
	cfg.HostName = "mdns-test"
	cfg.LogFunc = func(format string, args ...any) {
		fmt.Printf("[mdns] "+format+"\n", args...)
	}

	srv, err := mdns.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create server: %v\n", err)
		os.Exit(1)
	}
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start server: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()

	fmt.Printf("mDNS server started on port %d (hostname: %s)\n", *port, srv.HostName())

	switch *mode {
	case "resolve":
		runResolve(srv, *resolveHost)

	case "register":
		runRegister(srv, *serviceName, *serviceType, *svcPort)

	case "browse":
		runBrowse(srv, *serviceType)

	case "both":
		runRegister(srv, *serviceName, *serviceType, *svcPort)
		runBrowse(srv, *serviceType)
	}

	// Wait for Ctrl-C.
	fmt.Println("\nPress Ctrl-C to stop...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\nShutting down...")
}

func runRegister(srv *mdns.Server, name, svcType string, svcPort int) {
	svc := &mdns.ServiceInstance{
		Name: name,
		Type: svcType,
		Port: uint16(svcPort),
		Text: []string{"path=/", "version=1.0"},
	}
	if err := srv.RegisterService(svc); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to register service: %v\n", err)
		return
	}
	fmt.Printf("Registered service: %s type=%s port=%d\n", name, svcType, svcPort)
}

func runBrowse(srv *mdns.Server, svcType string) {
	browser, err := srv.Browse(svcType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create browser: %v\n", err)
		return
	}
	events, err := browser.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start browser: %v\n", err)
		return
	}

	go func() {
		for ev := range events {
			switch ev.Action {
			case mdns.EventAdd:
				fmt.Printf("[+] Service found: %s\n", ev.Instance)
			case mdns.EventRemove:
				fmt.Printf("[-] Service lost: %s\n", ev.Instance)
			}
		}
	}()
}

func runResolve(srv *mdns.Server, host string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := srv.ResolveHost(ctx, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve %s: %v\n", host, err)
		return
	}

	fmt.Printf("Resolved %s:\n", host)
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip)
	}
}
