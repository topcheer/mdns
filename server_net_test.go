package mdns

import (
	"context"
	"net"
	"testing"
	"time"
)

// ============================================================
// Test Server helpers for network-layer tests
// ============================================================

// newTestServerWithCtx creates a Server with ctx set up for goroutines
// that use s.ctx.Done(). conn remains nil — tests must avoid code paths
// that call s.conn.Write* directly.
func newTestServerWithCtx() *Server {
	srv, _ := NewServer(DefaultConfig())
	srv.ctx, srv.cancel = context.WithCancel(context.Background())
	srv.hostIPs = []net.IP{net.IPv4(127, 0, 0, 1)}
	return srv
}

// newTestServerWithService creates a Server with a registered, announced service
// so that handleQuery can find matching records.
func newTestServerWithService() *Server {
	srv := newTestServerWithCtx()

	inst := &ServiceInstance{
		Name:   "MyService",
		Type:   "_http._tcp",
		Domain: "local.",
		Port:   8080,
		Host:   "test.local.",
		IPs:    []net.IP{net.IPv4(10, 0, 0, 1)},
		Text:   []string{"path=/"},
	}

	records := srv.generateServiceRecords(inst)
	rs := &registeredService{
		instance: inst,
		records:  records,
		state:    stateAnnounced,
		probeCh:  make(chan struct{}),
	}

	srv.mu.Lock()
	srv.services[inst.InstanceName()] = rs
	srv.mu.Unlock()

	return srv
}

// ============================================================
// handleResponse tests
// ============================================================

func TestHandleResponse_CachesAnswers(t *testing.T) {
	srv := newTestServerWithCtx()

	msg := &Message{
		Header: Header{Flags: flagResponse},
		Answers: []*ResourceRecord{
			{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 5)},
		},
	}

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 5353}
	srv.handleResponse(msg, from)

	cached := srv.cache.Lookup(rrKey("host.local.", TypeA))
	if len(cached) != 1 {
		t.Fatalf("expected 1 cached record, got %d", len(cached))
	}
	if !cached[0].IP.Equal(net.IPv4(10, 0, 0, 5)) {
		t.Errorf("cached IP: got %s, want 10.0.0.5", cached[0].IP)
	}
}

func TestHandleResponse_CachesAdditionals(t *testing.T) {
	srv := newTestServerWithCtx()

	msg := &Message{
		Header: Header{Flags: flagResponse},
		Answers: []*ResourceRecord{
			{Name: "svc._http._tcp.local.", Type: TypePTR, Class: ClassIN, TTL: 300, Target: "inst._http._tcp.local."},
		},
		Additionals: []*ResourceRecord{
			{Name: "inst._http._tcp.local.", Type: TypeSRV, Class: ClassIN, TTL: 300, Port: 8080, Target: "host.local."},
			{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)},
		},
	}

	srv.handleResponse(msg, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99)})

	srvA := srv.cache.Lookup(rrKey("host.local.", TypeA))
	if len(srvA) != 1 {
		t.Errorf("expected 1 A record cached from additionals, got %d", len(srvA))
	}
	srvRR := srv.cache.Lookup(rrKey("inst._http._tcp.local.", TypeSRV))
	if len(srvRR) != 1 {
		t.Errorf("expected 1 SRV record cached from additionals, got %d", len(srvRR))
	}
}

func TestHandleResponse_GoodbyeRemovesRecord(t *testing.T) {
	srv := newTestServerWithCtx()

	// First, cache a record.
	rr := &ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}
	srv.cache.Upsert(rr, nil)

	// Now receive a goodbye (TTL=0) for the same record.
	goodbye := &ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 0, IP: net.IPv4(10, 0, 0, 1)}
	msg := &Message{
		Header:  Header{Flags: flagResponse},
		Answers: []*ResourceRecord{goodbye},
	}

	srv.handleResponse(msg, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99)})

	cached := srv.cache.Lookup(rrKey("host.local.", TypeA))
	if len(cached) != 0 {
		t.Errorf("expected 0 cached records after goodbye, got %d", len(cached))
	}
}

func TestHandleResponse_ClearsPassiveTracking(t *testing.T) {
	srv := newTestServerWithCtx()

	// Track some passive queries.
	srv.trackPassiveQuery("host.local.")
	srv.passiveMu.Lock()
	count := srv.passiveSeen["host.local."]
	srv.passiveMu.Unlock()
	if count != 1 {
		t.Fatalf("expected 1 passive query, got %d", count)
	}

	msg := &Message{
		Header: Header{Flags: flagResponse},
		Answers: []*ResourceRecord{
			{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)},
		},
	}

	srv.handleResponse(msg, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99)})

	srv.passiveMu.Lock()
	_, exists := srv.passiveSeen["host.local."]
	srv.passiveMu.Unlock()
	if exists {
		t.Error("passive tracking should be cleared after receiving response")
	}
}

// ============================================================
// handleQuery tests (no-response paths)
// ============================================================

func TestHandleQuery_NoMatch_NoPanic(t *testing.T) {
	srv := newTestServerWithCtx()

	msg := &Message{
		Header:    Header{Flags: 0},
		Questions: []*Question{{Name: "nonexistent.local.", Type: TypeA, Class: ClassIN}},
	}

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 5353}
	srv.handleQuery(msg, from)
	time.Sleep(50 * time.Millisecond)
}

func TestHandleQuery_TracksPassiveObservation(t *testing.T) {
	srv := newTestServerWithCtx()

	msg := &Message{
		Header:    Header{Flags: 0},
		Questions: []*Question{{Name: "_http._tcp.local.", Type: TypePTR, Class: ClassIN}},
	}

	srv.handleQuery(msg, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 5353})

	srv.passiveMu.Lock()
	count := srv.passiveSeen["_http._tcp.local."]
	srv.passiveMu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 passive observation, got %d", count)
	}
}

func TestHandleQuery_KnownAnswerSuppression(t *testing.T) {
	srv := newTestServerWithService()

	queryRR := &ResourceRecord{
		Name: "MyService._http._tcp.local.", Type: TypeSRV, Class: ClassIN, TTL: 300,
		Port: 8080, Target: "test.local.", Priority: 0, Weight: 0, CacheFlush: true,
	}

	msg := &Message{
		Header:    Header{Flags: 0},
		Questions: []*Question{{Name: "MyService._http._tcp.local.", Type: TypeSRV, Class: ClassIN}},
		Answers:   []*ResourceRecord{queryRR},
	}

	srv.handleQuery(msg, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 5353})
	time.Sleep(50 * time.Millisecond)
}

func TestHandleQuery_ProbeAuthority(t *testing.T) {
	srv := newTestServerWithService()

	probeRR := &ResourceRecord{
		Name: "other-host.local.", Type: TypeA, Class: ClassIN, IP: net.IPv4(10, 0, 0, 50),
	}

	msg := &Message{
		Header:      Header{Flags: 0},
		Questions:   []*Question{{Name: "other-host.local.", Type: TypeA, Class: ClassIN}},
		Authorities: []*ResourceRecord{probeRR},
	}

	srv.handleQuery(msg, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 5353})
	time.Sleep(50 * time.Millisecond)
}

// ============================================================
// handleProbe tests
// ============================================================

func TestHandleProbe_NoConflict(t *testing.T) {
	srv := newTestServerWithService()

	probeRR := &ResourceRecord{
		Name: "other-inst._http._tcp.local.", Type: TypeSRV, Class: ClassIN,
		Port: 9999, Target: "other.local.", CacheFlush: true,
	}

	srv.handleProbe(probeRR, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99)})

	srv.mu.RLock()
	for _, rs := range srv.services {
		if rs.state != stateAnnounced {
			t.Errorf("expected stateAnnounced, got %d", rs.state)
		}
	}
	srv.mu.RUnlock()
}

func TestHandleProbe_SelfLoopback(t *testing.T) {
	srv := newTestServerWithService()

	srv.mu.RLock()
	var ourSRV *ResourceRecord
	for _, rs := range srv.services {
		for _, rr := range rs.records {
			if rr.Type == TypeSRV {
				ourSRV = rr
				break
			}
		}
	}
	srv.mu.RUnlock()

	if ourSRV == nil {
		t.Fatal("no SRV record found in service")
	}

	probe := *ourSRV
	probe.CacheFlush = true

	srv.handleProbe(&probe, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})

	srv.mu.RLock()
	for _, rs := range srv.services {
		if rs.state != stateAnnounced {
			t.Errorf("expected stateAnnounced for self-loopback, got %d", rs.state)
		}
	}
	srv.mu.RUnlock()
}

func TestHandleProbe_ConflictWhileProbing_Loses(t *testing.T) {
	srv := newTestServerWithCtx()

	inst := &ServiceInstance{
		Name: "MyService", Type: "_http._tcp", Domain: "local.", Port: 8080,
		Host: "test.local.", IPs: []net.IP{net.IPv4(10, 0, 0, 1)},
	}
	records := srv.generateServiceRecords(inst)

	rs := &registeredService{
		instance: inst,
		records:  records,
		state:    stateProbing,
		probeCh:  make(chan struct{}),
	}

	srv.mu.Lock()
	srv.services[inst.InstanceName()] = rs
	srv.mu.Unlock()

	// Find our SRV record and probe with higher rdata to make us lose.
	var ourSRV *ResourceRecord
	for _, rr := range records {
		if rr.Type == TypeSRV && rr.CacheFlush {
			ourSRV = rr
			break
		}
	}
	if ourSRV == nil {
		t.Fatal("no unique SRV record found")
	}

	theirs := *ourSRV
	theirs.Port = ourSRV.Port + 1

	srv.handleProbe(&theirs, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99)})

	if rs.state != stateConflictLost {
		t.Errorf("expected stateConflictLost, got %d", rs.state)
	}
	select {
	case <-rs.probeCh:
		// Good — channel is closed.
	default:
		t.Error("expected probeCh to be closed after losing tiebreak")
	}
}

func TestHandleProbe_ConflictWhileProbing_Wins(t *testing.T) {
	srv := newTestServerWithCtx()

	inst := &ServiceInstance{
		Name: "MyService", Type: "_http._tcp", Domain: "local.", Port: 8080,
		Host: "test.local.", IPs: []net.IP{net.IPv4(10, 0, 0, 1)},
	}
	records := srv.generateServiceRecords(inst)

	rs := &registeredService{
		instance: inst,
		records:  records,
		state:    stateProbing,
		probeCh:  make(chan struct{}),
	}

	srv.mu.Lock()
	srv.services[inst.InstanceName()] = rs
	srv.mu.Unlock()

	var ourSRV *ResourceRecord
	for _, rr := range records {
		if rr.Type == TypeSRV && rr.CacheFlush {
			ourSRV = rr
			break
		}
	}

	theirs := *ourSRV
	theirs.Port = 0 // Lower than ourSRV.Port (8080) — we win

	srv.handleProbe(&theirs, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99)})

	if rs.state != stateProbing {
		t.Errorf("expected stateProbing (we won), got %d", rs.state)
	}
	select {
	case <-rs.probeCh:
		t.Error("probeCh should NOT be closed when we win tiebreak")
	default:
		// Good — channel is still open.
	}
}

// ============================================================
// detectConflictLocked tests
// ============================================================

func TestDetectConflictLocked_NoServices(t *testing.T) {
	srv := newTestServerWithCtx()

	rr := &ResourceRecord{Name: "host.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 1)}
	srv.mu.Lock()
	srv.detectConflictLocked(rr, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99)})
	srv.mu.Unlock()
}

func TestDetectConflictLocked_SelfLoopback(t *testing.T) {
	srv := newTestServerWithService()

	srv.mu.RLock()
	var ourRR *ResourceRecord
	for _, rs := range srv.services {
		for _, rr := range rs.records {
			if rr.CacheFlush {
				ourRR = rr
				break
			}
		}
	}
	srv.mu.RUnlock()

	if ourRR == nil {
		t.Fatal("no unique record found")
	}

	clone := *ourRR
	srv.mu.Lock()
	srv.detectConflictLocked(&clone, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	srv.mu.Unlock()
}

// ============================================================
// handleReverseMapping tests
// ============================================================

func TestHandleReverseMapping_IPv4(t *testing.T) {
	srv := newTestServerWithCtx()
	srv.hostIPs = []net.IP{net.IPv4(192, 168, 1, 50)}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	q := &Question{Name: "50.1.168.192.in-addr.arpa.", Type: TypePTR, Class: ClassIN}
	rr := srv.handleReverseMapping(q)

	if rr == nil {
		t.Fatal("expected non-nil PTR record")
	}
	if rr.Type != TypePTR {
		t.Errorf("type: got %d, want %d", rr.Type, TypePTR)
	}
}

func TestHandleReverseMapping_IPv4_WrongIP(t *testing.T) {
	srv := newTestServerWithCtx()
	srv.hostIPs = []net.IP{net.IPv4(192, 168, 1, 50)}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	q := &Question{Name: "99.1.168.192.in-addr.arpa.", Type: TypePTR, Class: ClassIN}
	rr := srv.handleReverseMapping(q)
	if rr != nil {
		t.Errorf("expected nil for non-owned IP")
	}
}

func TestHandleReverseMapping_NotReverseName(t *testing.T) {
	srv := newTestServerWithCtx()
	srv.hostIPs = []net.IP{net.IPv4(192, 168, 1, 50)}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	q := &Question{Name: "host.local.", Type: TypeA, Class: ClassIN}
	rr := srv.handleReverseMapping(q)
	if rr != nil {
		t.Error("expected nil for non-reverse name")
	}
}

func TestHandleReverseMapping_WrongType(t *testing.T) {
	srv := newTestServerWithCtx()
	srv.hostIPs = []net.IP{net.IPv4(192, 168, 1, 50)}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	q := &Question{Name: "50.1.168.192.in-addr.arpa.", Type: TypeA, Class: ClassIN}
	rr := srv.handleReverseMapping(q)
	if rr != nil {
		t.Error("expected nil for non-PTR query on reverse name")
	}
}

func TestHandleReverseMapping_TypeAny(t *testing.T) {
	srv := newTestServerWithCtx()
	srv.hostIPs = []net.IP{net.IPv4(192, 168, 1, 50)}

	srv.mu.RLock()
	defer srv.mu.RUnlock()

	q := &Question{Name: "50.1.168.192.in-addr.arpa.", Type: TypeAny, Class: ClassIN}
	rr := srv.handleReverseMapping(q)
	if rr == nil {
		t.Error("expected non-nil for TypeAny reverse query")
	}
}

// ============================================================
// Server accessor tests
// ============================================================

func TestServerCacheAccessor(t *testing.T) {
	srv := newTestServerWithCtx()
	if srv.Cache() == nil {
		t.Error("Cache() should not be nil")
	}
}

func TestServerConfigAccessor(t *testing.T) {
	srv := newTestServerWithCtx()
	cfg := srv.Config()
	if cfg.Port != DefaultPort {
		t.Errorf("Config().Port: got %d, want %d", cfg.Port, DefaultPort)
	}
}

func TestServerHostNameAccessor(t *testing.T) {
	srv := newTestServerWithCtx()
	if srv.HostName() == "" {
		t.Error("HostName() should not be empty")
	}
}

func TestServerHostIPsAccessor(t *testing.T) {
	srv := newTestServerWithCtx()
	ips := srv.HostIPs()
	if len(ips) != 1 {
		t.Errorf("HostIPs(): got %d IPs, want 1", len(ips))
	}
	if !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("HostIPs()[0]: got %s, want 127.0.0.1", ips[0])
	}
}

// ============================================================
// handlePacket integration tests
// ============================================================

func TestHandlePacket_InvalidData(t *testing.T) {
	srv := newTestServerWithCtx()
	pkt := ReceivedPacket{
		Data: []byte{0xFF, 0xFF, 0xFF, 0xFF},
		From: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 5353},
	}
	srv.handlePacket(pkt)
}

func TestHandlePacket_NonCompliantmDNS(t *testing.T) {
	srv := newTestServerWithCtx()

	msg := &Message{
		Header:    Header{Flags: 0x0800}, // opcode=1
		Questions: []*Question{{Name: "test.local.", Type: TypeA, Class: ClassIN}},
	}
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	pkt := ReceivedPacket{
		Data: data,
		From: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353},
	}
	srv.handlePacket(pkt)
}

func TestHandlePacket_ResponseFromNonLocal(t *testing.T) {
	srv := newTestServerWithCtx()

	msg := &Message{
		Header: Header{Flags: flagResponse},
		Answers: []*ResourceRecord{
			{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(8, 8, 8, 8)},
		},
	}
	data, _ := msg.Pack()

	pkt := ReceivedPacket{
		Data: data,
		From: &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 5353},
	}

	srv.handlePacket(pkt)

	cached := srv.cache.Lookup(rrKey("host.local.", TypeA))
	if len(cached) != 0 {
		t.Errorf("expected 0 cached records from non-local source, got %d", len(cached))
	}
}

func TestHandlePacket_ValidResponse(t *testing.T) {
	srv := newTestServerWithCtx()

	msg := &Message{
		Header: Header{Flags: flagResponse},
		Answers: []*ResourceRecord{
			{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 5)},
		},
	}
	data, _ := msg.Pack()

	pkt := ReceivedPacket{
		Data: data,
		From: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353},
	}

	srv.handlePacket(pkt)

	cached := srv.cache.Lookup(rrKey("host.local.", TypeA))
	if len(cached) != 1 {
		t.Errorf("expected 1 cached record, got %d", len(cached))
	}
}

// ============================================================
// notifyAddition / notifyRemoval tests
// ============================================================

func TestNotifyAdditionAndRemoval_NoBrowsers(t *testing.T) {
	srv := newTestServerWithCtx()

	rr := &ResourceRecord{Name: "test.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)}
	srv.notifyAddition(rr)
	srv.notifyRemoval(rr)
	// With no browsers registered, these should be no-ops without panic.
}

// ============================================================
// Cleanup / Shutdown tests
// ============================================================

func TestServerClose_WithoutStart(t *testing.T) {
	srv := newTestServerWithCtx()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Close panicked: %v", r)
		}
	}()
	srv.cancel()
}
