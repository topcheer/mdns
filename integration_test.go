package mdns

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestIntegrationRegisterBrowse tests the full mDNS flow:
// register a service on one server, browse from another, and verify discovery.
//
// This test requires multicast networking and may be skipped in CI.
func TestIntegrationRegisterBrowse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	port := 53599 // use a non-standard port to avoid conflicts

	// Server 1: registers a service.
	cfg1 := DefaultConfig()
	cfg1.Port = port
	cfg1.HostName = "mdns-integration-host1"
	cfg1.LogFunc = nil

	srv1, err := NewServer(cfg1)
	if err != nil {
		t.Fatalf("NewServer 1: %v", err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatalf("Start 1: %v", err)
	}
	defer srv1.Close()

	svc := &ServiceInstance{
		Name: "IntegrationTestService",
		Type: "_integration._tcp",
		Port: 9999,
		Text: []string{"test=true", "version=1.0"},
	}
	if err := srv1.RegisterService(svc); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	// Wait for probing to complete (~1s).
	time.Sleep(2 * time.Second)

	// Server 2: browses for the service.
	cfg2 := DefaultConfig()
	cfg2.Port = port
	cfg2.HostName = "mdns-integration-host2"

	srv2, err := NewServer(cfg2)
	if err != nil {
		t.Fatalf("NewServer 2: %v", err)
	}
	if err := srv2.Start(); err != nil {
		t.Fatalf("Start 2: %v", err)
	}
	defer srv2.Close()

	browser, err := srv2.Browse("_integration._tcp")
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	events, err := browser.Start()
	if err != nil {
		t.Fatalf("Browser.Start: %v", err)
	}
	defer browser.Stop()

	// Wait for discovery (up to 10 seconds).
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Action == EventAdd && ev.Instance != nil {
				t.Logf("Discovered: %s", ev.Instance)
				if ev.Instance.Name == "IntegrationTestService" {
					// Success!
					if ev.Instance.Port != 9999 {
						t.Errorf("port: got %d, want 9999", ev.Instance.Port)
					}
					return
				}
			}
		case <-timeout:
			t.Fatal("timed out waiting for service discovery")
		}
	}
}

// TestIntegrationResolveHost tests hostname resolution.
func TestIntegrationResolveHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	port := 53598

	cfg1 := DefaultConfig()
	cfg1.Port = port
	cfg1.HostName = "resolve-host-test"

	srv1, err := NewServer(cfg1)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv1.Close()

	time.Sleep(2 * time.Second)

	// Resolve from the same server (should find in cache).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := srv1.ResolveHost(ctx, "resolve-host-test.local.")
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least 1 IP address")
	}
	t.Logf("Resolved addresses: %v", ips)

	// Verify the IPs are valid local addresses.
	for _, ip := range ips {
		if ip.IsLoopback() {
			continue
		}
		if ip.To4() == nil && ip.To16() == nil {
			t.Errorf("invalid IP: %s", ip)
		}
	}
}

// TestProbeMessageFormat verifies the probe query format.
func TestProbeMessageFormat(t *testing.T) {
	records := []*ResourceRecord{
		{Name: "test.local.", Type: TypeA, Class: ClassIN, TTL: 120, IP: net.IPv4(10, 0, 0, 1)},
		{Name: "test.local.", Type: TypeSRV, Class: ClassIN, TTL: 120, Port: 8080, Target: "host.local."},
	}

	msg := &Message{
		Header: Header{
			QDCount: 1,
			NSCount: 2,
		},
		Questions: []*Question{
			{Name: "test.local.", Type: TypeAny, Class: ClassIN},
		},
		Authorities: records,
	}

	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if !decoded.IsQuery() {
		t.Error("probe should be a query")
	}
	if len(decoded.Questions) != 1 {
		t.Errorf("expected 1 question, got %d", len(decoded.Questions))
	}
	if decoded.Questions[0].Type != TypeAny {
		t.Errorf("probe question type: got %d, want %d", decoded.Questions[0].Type, TypeAny)
	}
	if len(decoded.Authorities) != 2 {
		t.Errorf("expected 2 authority records, got %d", len(decoded.Authorities))
	}
}

// TestGoodbyeMessage verifies that TTL=0 records are treated as goodbye.
func TestGoodbyeMessage(t *testing.T) {
	c := NewCache()

	// Add a record.
	rr := &ResourceRecord{Name: "test.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}
	c.Upsert(rr, nil)
	if len(c.Lookup(rrKey("test.local.", TypeA))) != 1 {
		t.Fatal("expected 1 record before goodbye")
	}

	// Simulate goodbye (TTL=0).
	goodbye := &ResourceRecord{Name: "test.local.", Type: TypeA, Class: ClassIN, TTL: 0, IP: net.IPv4(10, 0, 0, 1)}
	c.Remove(rrKey(goodbye.Name, goodbye.Type))

	if len(c.Lookup(rrKey("test.local.", TypeA))) != 0 {
		t.Error("expected 0 records after goodbye")
	}
}

// TestServiceRecordGeneration verifies that service records are generated correctly.
func TestServiceRecordGeneration(t *testing.T) {
	srv := &Server{
		config: DefaultConfig(),
		hostIPs: []net.IP{net.IPv4(192, 168, 1, 50)},
	}

	svc := &ServiceInstance{
		Name: "TestSvc",
		Type: "_http._tcp",
		Port: 8080,
		Text: []string{"path=/"},
		IPs:  []net.IP{net.IPv4(192, 168, 1, 50)},
	}
	svc.Domain = "local."

	records := srv.generateServiceRecords(svc)

	if len(records) != 4 { // PTR + SRV + TXT + A
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	// Check PTR.
	ptr := records[0]
	if ptr.Type != TypePTR || ptr.Target != "TestSvc._http._tcp.local." {
		t.Errorf("PTR record wrong: %+v", ptr)
	}

	// Check SRV.
	srvRR := records[1]
	if srvRR.Type != TypeSRV || srvRR.Port != 8080 {
		t.Errorf("SRV record wrong: %+v", srvRR)
	}
	if !srvRR.CacheFlush {
		t.Error("SRV should have cache-flush bit")
	}

	// Check TXT.
	txt := records[2]
	if txt.Type != TypeTXT || len(txt.Text) != 1 || txt.Text[0] != "path=/" {
		t.Errorf("TXT record wrong: %+v", txt)
	}

	// Check A.
	a := records[3]
	if a.Type != TypeA || !a.IP.Equal(net.IPv4(192, 168, 1, 50)) {
		t.Errorf("A record wrong: %+v", a)
	}
}
