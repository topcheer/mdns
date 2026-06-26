package mdns

import (
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// P1: Browser supplementary tests — 0% coverage functions
// Tests that don't require network I/O (no mock conn needed):
//   - Instances()
//   - onRecordRemove()
//   - resolveInstance()
//   - handlePTR()
//   - updateInstancesFromRecord()
//   - onRecordAdd()
//   - refreshExpiringRecords() (no-op / fresh records cases)
// ---------------------------------------------------------------------------

// newTestBrowser creates a Browser backed by a test server (no network).
func newTestBrowser(serviceType string) *Browser {
	srv := newTestServer()
	return &Browser{
		server:      srv,
		serviceType: normalizeServiceTypeDomain(serviceType, srv.config.Domain),
		domain:      srv.config.Domain,
		instances:   make(map[string]*ServiceInstanceInfo),
		cancel:      make(chan struct{}),
	}
}

// --- Instances ---

func TestBrowserInstancesEmpty(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	if got := b.Instances(); len(got) != 0 {
		t.Errorf("expected 0 instances from empty browser, got %d", len(got))
	}
}

func TestBrowserInstancesPopulated(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["svc1"] = &ServiceInstanceInfo{Name: "svc1", Port: 80}
	b.instances["svc2"] = &ServiceInstanceInfo{Name: "svc2", Port: 443}
	b.instances["svc3"] = &ServiceInstanceInfo{Name: "svc3", Port: 8080}

	got := b.Instances()
	if len(got) != 3 {
		t.Fatalf("expected 3 instances, got %d", len(got))
	}

	// Verify all expected instances are present (map iteration order is random).
	names := make(map[string]bool)
	for _, info := range got {
		names[info.Name] = true
	}
	for _, expected := range []string{"svc1", "svc2", "svc3"} {
		if !names[expected] {
			t.Errorf("missing instance %q", expected)
		}
	}
}

// --- onRecordRemove ---

func TestBrowserOnRecordRemovePTR(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "web",
		Type: "_http._tcp.local.",
	}

	// Remove via PTR goodbye.
	b.onRecordRemove(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_http._tcp.local.",
		Target: "web._http._tcp.local.",
	})

	if len(b.instances) != 0 {
		t.Errorf("expected 0 instances after remove, got %d", len(b.instances))
	}
}

func TestBrowserOnRecordRemoveNonPTR(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{Name: "web"}

	// Non-PTR records should be ignored by onRecordRemove.
	b.onRecordRemove(&ResourceRecord{
		Type: TypeA,
		Name: "web._http._tcp.local.",
		IP:   net.IPv4(10, 0, 0, 1),
	})

	if len(b.instances) != 1 {
		t.Errorf("expected 1 instance (non-PTR should be ignored), got %d", len(b.instances))
	}
}

func TestBrowserOnRecordRemoveWrongServiceType(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{Name: "web"}

	// PTR for a different service type.
	b.onRecordRemove(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_ftp._tcp.local.",
		Target: "web._ftp._tcp.local.",
	})

	if len(b.instances) != 1 {
		t.Errorf("expected 1 instance (wrong service type), got %d", len(b.instances))
	}
}

func TestBrowserOnRecordRemoveNonExistentInstance(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	// No instances.

	b.onRecordRemove(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_http._tcp.local.",
		Target: "ghost._http._tcp.local.",
	})

	// Should not panic, should be no-op.
	if len(b.instances) != 0 {
		t.Errorf("expected 0 instances, got %d", len(b.instances))
	}
}

func TestBrowserOnRecordRemoveNotifiesListeners(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "web",
		Port: 80,
	}

	// Set up a listener.
	ch := make(chan ServiceEvent, 1)
	b.listeners = append(b.listeners, ch)

	b.onRecordRemove(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_http._tcp.local.",
		Target: "web._http._tcp.local.",
	})

	select {
	case evt := <-ch:
		if evt.Action != EventRemove {
			t.Errorf("expected EventRemove, got %d", evt.Action)
		}
		if evt.Instance.Name != "web" {
			t.Errorf("expected instance 'web', got %q", evt.Instance.Name)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("did not receive EventRemove notification")
	}
}

// --- resolveInstance ---

func TestBrowserResolveInstanceComplete(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	cache := b.server.cache

	// Populate cache with SRV, TXT, A records.
	cache.Upsert(&ResourceRecord{
		Name: "web._http._tcp.local.", Type: TypeSRV, Class: ClassIN, TTL: 300,
		Priority: 10, Weight: 5, Port: 8080, Target: "host.local.",
	}, nil)
	cache.Upsert(&ResourceRecord{
		Name: "web._http._tcp.local.", Type: TypeTXT, Class: ClassIN, TTL: 300,
		Text: []string{"path=/", "v=2"},
	}, nil)
	cache.Upsert(&ResourceRecord{
		Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300,
		IP: net.IPv4(192, 168, 1, 50),
	}, nil)
	cache.Upsert(&ResourceRecord{
		Name: "host.local.", Type: TypeAAAA, Class: ClassIN, TTL: 300,
		IP: net.ParseIP("fe80::1234"),
	}, nil)

	info := b.resolveInstance("web._http._tcp.local.")
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info.Host != "host.local." {
		t.Errorf("host: got %q, want host.local.", info.Host)
	}
	if info.Port != 8080 {
		t.Errorf("port: got %d, want 8080", info.Port)
	}
	if info.Priority != 10 {
		t.Errorf("priority: got %d, want 10", info.Priority)
	}
	if info.Weight != 5 {
		t.Errorf("weight: got %d, want 5", info.Weight)
	}
	if len(info.Text) != 2 {
		t.Errorf("text length: got %d, want 2", len(info.Text))
	}
	if len(info.IPs) != 2 {
		t.Errorf("IPs length: got %d, want 2", len(info.IPs))
	}
}

func TestBrowserResolveInstanceNoSRV(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	// Cache has no SRV record for this instance.

	info := b.resolveInstance("absent._http._tcp.local.")
	if info != nil {
		t.Errorf("expected nil for missing SRV, got %+v", info)
	}
}

func TestBrowserResolveInstancePartial(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	cache := b.server.cache

	// Only SRV, no TXT/A/AAAA.
	cache.Upsert(&ResourceRecord{
		Name: "web._http._tcp.local.", Type: TypeSRV, Class: ClassIN, TTL: 300,
		Port: 443, Target: "host.local.",
	}, nil)

	info := b.resolveInstance("web._http._tcp.local.")
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info.Port != 443 {
		t.Errorf("port: got %d, want 443", info.Port)
	}
	if len(info.Text) != 0 {
		t.Errorf("text: expected empty, got %v", info.Text)
	}
	if len(info.IPs) != 0 {
		t.Errorf("IPs: expected empty, got %v", info.IPs)
	}
}

// --- handlePTR ---

func TestBrowserHandlePTRNewInstance(t *testing.T) {
	b := newTestBrowser("_http._tcp")

	// Set up listener.
	ch := make(chan ServiceEvent, 1)
	b.listeners = append(b.listeners, ch)

	b.handlePTR(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_http._tcp.local.",
		Target: "web._http._tcp.local.",
	})

	if len(b.instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(b.instances))
	}

	select {
	case evt := <-ch:
		if evt.Action != EventAdd {
			t.Errorf("expected EventAdd, got %d", evt.Action)
		}
	default:
		t.Error("did not receive EventAdd")
	}
}

func TestBrowserHandlePTRDuplicate(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{Name: "web"}

	b.handlePTR(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_http._tcp.local.",
		Target: "web._http._tcp.local.",
	})

	// Should remain 1 (duplicate ignored).
	if len(b.instances) != 1 {
		t.Errorf("expected 1 instance (duplicate ignored), got %d", len(b.instances))
	}
}

func TestBrowserHandlePTRWithCachedSRV(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	cache := b.server.cache

	// Pre-populate SRV record so resolveInstance returns full info.
	cache.Upsert(&ResourceRecord{
		Name: "web._http._tcp.local.", Type: TypeSRV, Class: ClassIN, TTL: 300,
		Port: 80, Target: "host.local.",
	}, nil)
	cache.Upsert(&ResourceRecord{
		Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300,
		IP: net.IPv4(10, 0, 0, 1),
	}, nil)

	b.handlePTR(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_http._tcp.local.",
		Target: "web._http._tcp.local.",
	})

	info := b.instances["web._http._tcp.local."]
	if info == nil {
		t.Fatal("expected instance to be added")
	}
	if info.Port != 80 {
		t.Errorf("port: got %d, want 80", info.Port)
	}
	if info.Host != "host.local." {
		t.Errorf("host: got %q, want host.local.", info.Host)
	}
	if len(info.IPs) != 1 {
		t.Errorf("IPs: expected 1, got %d", len(info.IPs))
	}
}

// --- updateInstancesFromRecord ---

func TestBrowserUpdateSRVRecord(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "web",
		Type: "_http._tcp.local.",
		Host: "old.local.",
		Port: 80,
	}

	b.updateInstancesFromRecord(&ResourceRecord{
		Name:     "web._http._tcp.local.",
		Type:     TypeSRV,
		Priority: 20,
		Weight:   10,
		Port:     8080,
		Target:   "new.local.",
	})

	info := b.instances["web._http._tcp.local."]
	if info.Host != "new.local." {
		t.Errorf("host: got %q, want new.local.", info.Host)
	}
	if info.Port != 8080 {
		t.Errorf("port: got %d, want 8080", info.Port)
	}
	if info.Priority != 20 {
		t.Errorf("priority: got %d, want 20", info.Priority)
	}
}

func TestBrowserUpdateTXTRecord(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "web",
		Text: []string{"old=1"},
	}

	b.updateInstancesFromRecord(&ResourceRecord{
		Name: "web._http._tcp.local.",
		Type: TypeTXT,
		Text: []string{"new=2", "updated=true"},
	})

	info := b.instances["web._http._tcp.local."]
	if len(info.Text) != 2 {
		t.Fatalf("text length: got %d, want 2", len(info.Text))
	}
	if info.Text[0] != "new=2" {
		t.Errorf("text[0]: got %q, want new=2", info.Text[0])
	}
}

func TestBrowserUpdateARecordAddsIP(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "web._http._tcp.local.",
		Host: "host.local.",
		IPs:  []net.IP{net.IPv4(10, 0, 0, 1)},
	}

	b.updateInstancesFromRecord(&ResourceRecord{
		Name: "host.local.",
		Type: TypeA,
		IP:   net.IPv4(10, 0, 0, 2),
	})

	info := b.instances["web._http._tcp.local."]
	if len(info.IPs) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(info.IPs))
	}
}

func TestBrowserUpdateARecordDuplicateIP(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "web._http._tcp.local.",
		Host: "host.local.",
		IPs:  []net.IP{net.IPv4(10, 0, 0, 1)},
	}

	b.updateInstancesFromRecord(&ResourceRecord{
		Name: "host.local.",
		Type: TypeA,
		IP:   net.IPv4(10, 0, 0, 1), // same IP
	})

	info := b.instances["web._http._tcp.local."]
	if len(info.IPs) != 1 {
		t.Errorf("expected 1 IP (duplicate not added), got %d", len(info.IPs))
	}
}

func TestBrowserUpdateRecordNoInstances(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	// No instances registered.

	// Should not panic.
	b.updateInstancesFromRecord(&ResourceRecord{
		Name: "anything.local.",
		Type: TypeSRV,
		Port: 80,
	})
}

// --- onRecordAdd ---

func TestBrowserOnRecordAddPTR(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	ch := make(chan ServiceEvent, 1)
	b.listeners = append(b.listeners, ch)

	b.onRecordAdd(&ResourceRecord{
		Type:   TypePTR,
		Name:   "_http._tcp.local.",
		Target: "svc._http._tcp.local.",
	})

	if len(b.instances) != 1 {
		t.Fatalf("expected 1 instance after PTR add, got %d", len(b.instances))
	}
	select {
	case evt := <-ch:
		if evt.Action != EventAdd {
			t.Error("expected EventAdd")
		}
	default:
		t.Error("no event received")
	}
}

func TestBrowserOnRecordAddNonPTR(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["svc._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "svc._http._tcp.local.",
		Host: "host.local.",
		Port: 80,
	}

	// An A record for the host should update the instance.
	b.onRecordAdd(&ResourceRecord{
		Name: "host.local.",
		Type: TypeA,
		IP:   net.IPv4(10, 0, 0, 5),
	})

	info := b.instances["svc._http._tcp.local."]
	if info == nil {
		t.Fatal("instance missing")
	}
	// The IP should have been added via updateInstancesFromRecord.
	found := false
	for _, ip := range info.IPs {
		if ip.Equal(net.IPv4(10, 0, 0, 5)) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected IP 10.0.0.5 in instance IPs, got %v", info.IPs)
	}
}

func TestBrowserOnRecordAddIrrelevantType(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	b.instances["svc._http._tcp.local."] = &ServiceInstanceInfo{Name: "svc"}

	// NSEC records should be ignored by onRecordAdd.
	b.onRecordAdd(&ResourceRecord{
		Name:       "host.local.",
		Type:       TypeNSEC,
		NextDomain: "next.local.",
	})

	// Should still have 1 instance, no changes.
	if len(b.instances) != 1 {
		t.Errorf("expected 1 instance, got %d", len(b.instances))
	}
}

// --- refreshExpiringRecords ---

func TestBrowserRefreshExpiringRecordsEmpty(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	// No instances, should be no-op (no panic).
	b.refreshExpiringRecords()
}

func TestBrowserRefreshExpiringRecordsFreshRecords(t *testing.T) {
	b := newTestBrowser("_http._tcp")
	cache := b.server.cache

	b.instances["web._http._tcp.local."] = &ServiceInstanceInfo{
		Name: "web",
		Type: "_http._tcp.local.",
	}
	cache.Upsert(&ResourceRecord{
		Name: "web._http._tcp.local.", Type: TypeSRV, Class: ClassIN, TTL: 300,
		Port: 80, Target: "host.local.",
	}, nil)

	// Records are fresh (remaining TTL > 20% of original).
	// This should NOT attempt to send (conn is nil, would panic).
	b.refreshExpiringRecords()
	// If we get here without panicking, the test passes.
}
