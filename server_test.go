package mdns

import (
	"net"
	"testing"
	"time"
)

// ============================================================
// P0: server.go pure/utility function tests
// ============================================================

// --- matchesQuestion ---

func TestMatchesQuestion(t *testing.T) {
	rr := &ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN}

	tests := []struct {
		name string
		rr   *ResourceRecord
		q    *Question
		want bool
	}{
		{"exact match", rr, &Question{Name: "host.local.", Type: TypeA, Class: ClassIN}, true},
		{"case-insensitive name", rr, &Question{Name: "Host.Local.", Type: TypeA, Class: ClassIN}, true},
		{"wrong type", rr, &Question{Name: "host.local.", Type: TypeAAAA, Class: ClassIN}, false},
		{"wrong name", rr, &Question{Name: "other.local.", Type: TypeA, Class: ClassIN}, false},
		{"TypeAny matches by name", rr, &Question{Name: "host.local.", Type: TypeAny, Class: ClassIN}, true},
		{"TypeAny wrong name", rr, &Question{Name: "other.local.", Type: TypeAny, Class: ClassIN}, false},
		{"ClassAny matches", rr, &Question{Name: "host.local.", Type: TypeA, Class: ClassAny}, true},
		{"cache-flush bit in question class", rr, &Question{Name: "host.local.", Type: TypeA, Class: ClassIN | cacheFlushBit}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesQuestion(tt.rr, tt.q)
			if got != tt.want {
				t.Errorf("matchesQuestion: got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- inKnownAnswers ---

func TestInKnownAnswers(t *testing.T) {
	rr := &ResourceRecord{Name: "test.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}

	tests := []struct {
		name     string
		rr       *ResourceRecord
		known    []*ResourceRecord
		want     bool
	}{
		{
			"no known answers",
			rr,
			nil,
			false,
		},
		{
			"exact match sufficient TTL",
			rr,
			[]*ResourceRecord{{Name: "test.local.", Type: TypeA, TTL: 200, IP: net.IPv4(10, 0, 0, 1)}},
			true, // 200 >= 300/2=150
		},
		{
			"exact match insufficient TTL",
			rr,
			[]*ResourceRecord{{Name: "test.local.", Type: TypeA, TTL: 100, IP: net.IPv4(10, 0, 0, 1)}},
			false, // 100 < 300/2=150
		},
		{
			"exact match at exactly half TTL",
			rr,
			[]*ResourceRecord{{Name: "test.local.", Type: TypeA, TTL: 150, IP: net.IPv4(10, 0, 0, 1)}},
			true, // 150 >= 150
		},
		{
			"different RDATA not suppressed",
			rr,
			[]*ResourceRecord{{Name: "test.local.", Type: TypeA, TTL: 300, IP: net.IPv4(10, 0, 0, 2)}},
			false,
		},
		{
			"different name not suppressed",
			rr,
			[]*ResourceRecord{{Name: "other.local.", Type: TypeA, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inKnownAnswers(tt.rr, tt.known)
			if got != tt.want {
				t.Errorf("inKnownAnswers: got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- containsRR ---

func TestContainsRR(t *testing.T) {
	records := []*ResourceRecord{
		{Name: "a.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
		{Name: "b.local.", Type: TypeSRV, Port: 8080, Target: "host.local."},
	}

	tests := []struct {
		name    string
		records []*ResourceRecord
		rr      *ResourceRecord
		want    bool
	}{
		{"contains A", records, &ResourceRecord{Name: "a.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)}, true},
		{"not contains different IP", records, &ResourceRecord{Name: "a.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 5)}, false},
		{"contains SRV", records, &ResourceRecord{Name: "b.local.", Type: TypeSRV, Port: 8080, Target: "host.local."}, true},
		{"empty list", nil, &ResourceRecord{Name: "a.local.", Type: TypeA}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsRR(tt.records, tt.rr)
			if got != tt.want {
				t.Errorf("containsRR: got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- recordsConflict ---

func TestRecordsConflict(t *testing.T) {
	tests := []struct {
		name string
		a, b *ResourceRecord
		want bool
	}{
		{
			"same name+type same RDATA = no conflict",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			false,
		},
		{
			"same name+type different RDATA = conflict",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 5)},
			true,
		},
		{
			"different type = no conflict",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "h.local.", Type: TypeAAAA, IP: net.IPv4(1, 2, 3, 4)},
			false,
		},
		{
			"different name = no conflict",
			&ResourceRecord{Name: "a.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "b.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			false,
		},
		{
			"case-insensitive name comparison",
			&ResourceRecord{Name: "Host.Local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "host.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 5)},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := recordsConflict(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("recordsConflict: got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- probeLoses ---

func TestProbeLoses(t *testing.T) {
	tests := []struct {
		name       string
		ours       *ResourceRecord
		theirs     *ResourceRecord
		weLose     bool
	}{
		{
			"lower IP loses",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 1)},
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 2)},
			true, // 10.0.0.1 < 10.0.0.2
		},
		{
			"higher IP wins",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 5)},
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 2)},
			false, // 10.0.0.5 > 10.0.0.2
		},
		{
			"equal RDATA = no loss",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 1)},
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 1)},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := probeLoses(tt.ours, tt.theirs)
			if got != tt.weLose {
				t.Errorf("probeLoses: got %v, want %v", got, tt.weLose)
			}
		})
	}
}

// --- canonicalRDATA ---

func TestCanonicalRDATA(t *testing.T) {
	t.Run("A record", func(t *testing.T) {
		rr := &ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(192, 168, 1, 1)}
		data := canonicalRDATA(rr)
		expected := []byte{192, 168, 1, 1}
		if string(data) != string(expected) {
			t.Errorf("canonicalRDATA A: got %v, want %v", data, expected)
		}
	})

	t.Run("AAAA record", func(t *testing.T) {
		ip6 := net.ParseIP("fe80::1")
		rr := &ResourceRecord{Name: "h.local.", Type: TypeAAAA, IP: ip6}
		data := canonicalRDATA(rr)
		if len(data) != 16 {
			t.Errorf("canonicalRDATA AAAA: expected 16 bytes, got %d", len(data))
		}
	})

	t.Run("SRV record", func(t *testing.T) {
		rr := &ResourceRecord{
			Name:     "inst._tcp.local.",
			Type:     TypeSRV,
			Priority: 0,
			Weight:   10,
			Port:     8080,
			Target:   "host.local.",
		}
		data := canonicalRDATA(rr)
		if len(data) < 6 { // 2+2+2 bytes for pri+weight+port + name
			t.Errorf("canonicalRDATA SRV: too short, got %d bytes", len(data))
		}
		// Verify priority bytes (big-endian).
		if data[0] != 0 || data[1] != 0 {
			t.Errorf("canonicalRDATA SRV priority: got %d %d, want 0 0", data[0], data[1])
		}
	})

	t.Run("TXT record", func(t *testing.T) {
		rr := &ResourceRecord{
			Name: "test.local.",
			Type: TypeTXT,
			Text: []string{"abc", "de"},
		}
		data := canonicalRDATA(rr)
		// Expected: len("abc") + "abc" + len("de") + "de" = 3+abc+2+de = 8 bytes
		expected := []byte{3, 'a', 'b', 'c', 2, 'd', 'e'}
		if string(data) != string(expected) {
			t.Errorf("canonicalRDATA TXT: got %v, want %v", data, expected)
		}
	})

	t.Run("PTR record", func(t *testing.T) {
		rr := &ResourceRecord{
			Name:   "_tcp.local.",
			Type:   TypePTR,
			Target: "inst._tcp.local.",
		}
		data := canonicalRDATA(rr)
		if len(data) == 0 {
			t.Error("canonicalRDATA PTR: empty data")
		}
	})

	t.Run("nil IP for A record", func(t *testing.T) {
		rr := &ResourceRecord{Name: "h.local.", Type: TypeA, IP: nil}
		data := canonicalRDATA(rr)
		if len(data) != 0 {
			t.Errorf("canonicalRDATA A nil IP: expected empty, got %d bytes", len(data))
		}
	})
}

// --- rdataKey ---

func TestRdataKey(t *testing.T) {
	tests := []struct {
		name string
		rr   *ResourceRecord
		want string
	}{
		{"A record", &ResourceRecord{Type: TypeA, IP: net.IPv4(10, 0, 0, 1)}, "10.0.0.1"},
		{"AAAA record", &ResourceRecord{Type: TypeAAAA, IP: net.ParseIP("fe80::1")}, "fe80::1"},
		{"PTR record", &ResourceRecord{Type: TypePTR, Target: "Inst._tcp.local."}, "inst._tcp.local."},
		{"SRV record", &ResourceRecord{Type: TypeSRV, Target: "Host.local.", Port: 8080}, "host.local.:8080"},
		{"TXT record", &ResourceRecord{Type: TypeTXT, Text: []string{"a", "b"}}, "a,b"},
		{"nil IP A record", &ResourceRecord{Type: TypeA, IP: nil}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rdataKey(tt.rr)
			if got != tt.want {
				t.Errorf("rdataKey: got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- reverseNameToIP ---

func TestReverseNameToIP(t *testing.T) {
	t.Run("IPv4 reverse", func(t *testing.T) {
		ip := reverseNameToIP("100.1.168.192.in-addr.arpa.")
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}
		expected := net.IPv4(192, 168, 1, 100)
		if !ip.Equal(expected) {
			t.Errorf("got %s, want %s", ip, expected)
		}
	})

	t.Run("IPv4 reverse no trailing dot", func(t *testing.T) {
		ip := reverseNameToIP("1.0.0.127.in-addr.arpa")
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}
		if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("got %s, want 127.0.0.1", ip)
		}
	})

	t.Run("not a reverse name", func(t *testing.T) {
		ip := reverseNameToIP("host.local.")
		if ip != nil {
			t.Errorf("expected nil for non-reverse name, got %s", ip)
		}
	})

	t.Run("invalid IPv4 reverse - wrong parts count", func(t *testing.T) {
		ip := reverseNameToIP("1.2.in-addr.arpa.")
		if ip != nil {
			t.Errorf("expected nil for invalid reverse name, got %s", ip)
		}
	})

	t.Run("invalid IPv4 reverse - out of range octet", func(t *testing.T) {
		ip := reverseNameToIP("256.1.1.1.in-addr.arpa.")
		if ip != nil {
			t.Errorf("expected nil for out-of-range octet, got %s", ip)
		}
	})

	t.Run("IPv6 reverse", func(t *testing.T) {
		// fe80::1 → reverse: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.
		name := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."
		ip := reverseNameToIP(name)
		if ip == nil {
			t.Fatal("expected non-nil IP for IPv6 reverse")
		}
		expected := net.ParseIP("fe80::1")
		if !ip.Equal(expected) {
			t.Errorf("got %s, want %s", ip, expected)
		}
	})

	t.Run("IPv6 reverse wrong nibble count", func(t *testing.T) {
		ip := reverseNameToIP("1.2.3.ip6.arpa.")
		if ip != nil {
			t.Errorf("expected nil for invalid IPv6 reverse, got %s", ip)
		}
	})
}

// --- hexNibble ---

func TestHexNibble(t *testing.T) {
	tests := []struct {
		input string
		want  int
		err   bool
	}{
		{"0", 0, false},
		{"9", 9, false},
		{"a", 10, false},
		{"f", 15, false},
		{"A", 10, false},
		{"F", 15, false},
		{"g", 0, true},
		{"", 0, true},
		{"10", 0, true}, // too long
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := hexNibble(tt.input)
			if tt.err {
				if err == nil {
					t.Errorf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("hexNibble(%q): got %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// --- defaultHostName ---

func TestDefaultHostName(t *testing.T) {
	name := defaultHostName()
	if name == "" {
		t.Error("defaultHostName returned empty string")
	}
	// Should only contain alphanumeric and hyphens.
	for _, r := range name {
		valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-'
		if !valid {
			t.Errorf("defaultHostName contains invalid char %q in %q", r, name)
		}
	}
}

// --- generateNSEC ---

func TestGenerateNSEC(t *testing.T) {
	srv := newTestServer()

	t.Run("records exist for name", func(t *testing.T) {
		records := []*ResourceRecord{
			{Name: "host.local.", Type: TypeA, Class: ClassIN},
			{Name: "host.local.", Type: TypeSRV, Class: ClassIN},
			{Name: "other.local.", Type: TypeA, Class: ClassIN}, // different name
		}
		nsec := srv.generateNSEC("host.local.", records)
		if nsec == nil {
			t.Fatal("expected non-nil NSEC")
		}
		if nsec.Type != TypeNSEC {
			t.Errorf("type: got %d, want %d", nsec.Type, TypeNSEC)
		}
		if nsec.Name != "host.local." {
			t.Errorf("name: got %q, want %q", nsec.Name, "host.local.")
		}
		if len(nsec.TypeBitMaps) != 2 {
			t.Errorf("expected 2 type bitmaps, got %d", len(nsec.TypeBitMaps))
		}
		// Should list A (1) and SRV (33).
		hasA, hasSRV := false, false
		for _, bt := range nsec.TypeBitMaps {
			if bt == TypeA {
				hasA = true
			}
			if bt == TypeSRV {
				hasSRV = true
			}
		}
		if !hasA {
			t.Error("NSEC should include TypeA")
		}
		if !hasSRV {
			t.Error("NSEC should include TypeSRV")
		}
	})

	t.Run("no records for name", func(t *testing.T) {
		records := []*ResourceRecord{
			{Name: "other.local.", Type: TypeA},
		}
		nsec := srv.generateNSEC("host.local.", records)
		if nsec != nil {
			t.Error("expected nil NSEC when no records match name")
		}
	})

	t.Run("empty records", func(t *testing.T) {
		nsec := srv.generateNSEC("host.local.", nil)
		if nsec != nil {
			t.Error("expected nil NSEC for empty records")
		}
	})
}

// --- canSendMulticast ---

func TestCanSendMulticast(t *testing.T) {
	srv := newTestServer()

	rr := &ResourceRecord{Name: "test.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 1)}

	// First send should be allowed.
	if !srv.canSendMulticast(rr) {
		t.Error("first canSendMulticast should be true")
	}

	// Immediate second send should be rate-limited.
	if srv.canSendMulticast(rr) {
		t.Error("second immediate canSendMulticast should be false (rate limited)")
	}
}

func TestCanSendMulticastDifferentRecords(t *testing.T) {
	srv := newTestServer()

	rr1 := &ResourceRecord{Name: "a.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 1)}
	rr2 := &ResourceRecord{Name: "b.local.", Type: TypeA, IP: net.IPv4(10, 0, 0, 2)}

	// Different records should not rate-limit each other.
	if !srv.canSendMulticast(rr1) {
		t.Error("first record should be allowed")
	}
	if !srv.canSendMulticast(rr2) {
		t.Error("second different record should be allowed")
	}
}

// --- isLocalSubnet ---

func TestIsLocalSubnet(t *testing.T) {
	srv := newTestServer()

	t.Run("loopback is local", func(t *testing.T) {
		if !srv.isLocalSubnet(net.IPv4(127, 0, 0, 1)) {
			t.Error("loopback should be considered local")
		}
	})

	t.Run("link-local is local", func(t *testing.T) {
		linkLocal := net.ParseIP("169.254.1.1")
		if !srv.isLocalSubnet(linkLocal) {
			t.Error("link-local should be considered local")
		}
	})

	t.Run("configured subnet match", func(t *testing.T) {
		_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
		srv.localSubnets = []*net.IPNet{subnet}
		if !srv.isLocalSubnet(net.IPv4(192, 168, 1, 50)) {
			t.Error("192.168.1.50 should be in configured subnet")
		}
	})

	t.Run("no subnet match", func(t *testing.T) {
		srv.localSubnets = nil
		// Non-loopback, non-link-local without configured subnets.
		ip := net.IPv4(8, 8, 8, 8)
		if srv.isLocalSubnet(ip) {
			t.Error("8.8.8.8 should not be local without configured subnets")
		}
	})
}

// --- cleanupRateTracker ---

func TestCleanupRateTracker(t *testing.T) {
	srv := newTestServer()

	// Populate rate tracker: one entry >5s old, one fresh.
	srv.rateMu.Lock()
	srv.rateTracker["old.local.:1:10.0.0.1"] = time.Now().Add(-6 * time.Second)
	srv.rateTracker["new.local.:1:10.0.0.2"] = time.Now()
	srv.rateMu.Unlock()

	srv.cleanupRateTracker()

	srv.rateMu.Lock()
	defer srv.rateMu.Unlock()
	if len(srv.rateTracker) != 1 {
		t.Errorf("expected 1 entry after cleanup, got %d", len(srv.rateTracker))
	}
	if _, ok := srv.rateTracker["new.local.:1:10.0.0.2"]; !ok {
		t.Error("recent entry should have been kept")
	}
}

// --- NewServer ---

func TestNewServerDefaults(t *testing.T) {
	cfg := Config{}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if srv.config.Port != DefaultPort {
		t.Errorf("port: got %d, want %d", srv.config.Port, DefaultPort)
	}
	if srv.config.Domain != DefaultDomain {
		t.Errorf("domain: got %q, want %q", srv.config.Domain, DefaultDomain)
	}
	if srv.config.HostName == "" {
		t.Error("hostname should not be empty")
	}
	if !hasSuffix(srv.config.HostName, "."+DefaultDomain) {
		t.Errorf("hostname should end with domain: got %q", srv.config.HostName)
	}
	if srv.cache == nil {
		t.Error("cache should not be nil")
	}
	if srv.services == nil {
		t.Error("services map should not be nil")
	}
}

func TestNewServerCustomConfig(t *testing.T) {
	cfg := Config{
		Port:     9999,
		Domain:   "test.",
		HostName: "myhost",
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if srv.config.Port != 9999 {
		t.Errorf("port: got %d, want 9999", srv.config.Port)
	}
	if srv.config.Domain != "test." {
		t.Errorf("domain: got %q, want %q", srv.config.Domain, "test.")
	}
	if srv.config.HostName != "myhost.test." {
		t.Errorf("hostname: got %q, want %q", srv.config.HostName, "myhost.test.")
	}
}

func TestNewServerHostNameWithDomain(t *testing.T) {
	cfg := Config{
		HostName: "explicit.local.",
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Should not double-append domain if hostname already ends with dot.
	if srv.config.HostName != "explicit.local." {
		t.Errorf("hostname: got %q, want %q", srv.config.HostName, "explicit.local.")
	}
}

// ============================================================
// P1: browser.go pure function tests
// ============================================================

// --- normalizeServiceTypeDomain ---

func TestNormalizeServiceTypeDomain(t *testing.T) {
	tests := []struct {
		name        string
		serviceType string
		domain      string
		want        string
	}{
		{"bare type", "_http._tcp", "local.", "_http._tcp.local."},
		{"with domain suffix", "_http._tcp.local", "local.", "_http._tcp.local."},
		{"with trailing dot", "_http._tcp.local.", "local.", "_http._tcp.local."},
		{"custom domain", "_http._tcp", "test.", "_http._tcp.test."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeServiceTypeDomain(tt.serviceType, tt.domain)
			if got != tt.want {
				t.Errorf("normalizeServiceTypeDomain(%q, %q): got %q, want %q",
					tt.serviceType, tt.domain, got, tt.want)
			}
		})
	}
}

// --- extractInstanceName ---

func TestExtractInstanceName(t *testing.T) {
	tests := []struct {
		name         string
		instanceName string
		serviceType  string
		want         string
	}{
		{
			"standard instance",
			"My Service._http._tcp.local.",
			"_http._tcp.local.",
			"My Service",
		},
		{
			"instance with dots in name",
			"My.App._http._tcp.local.",
			"_http._tcp.local.",
			"My.App",
		},
		{
			"no service type suffix match",
			"just-a-name",
			"_http._tcp.local.",
			"just-a-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractInstanceName(tt.instanceName, tt.serviceType)
			if got != tt.want {
				t.Errorf("extractInstanceName(%q, %q): got %q, want %q",
					tt.instanceName, tt.serviceType, got, tt.want)
			}
		})
	}
}

// --- copyServiceInstanceInfo ---

func TestCopyServiceInstanceInfo(t *testing.T) {
	original := &ServiceInstanceInfo{
		Name:     "test",
		Type:     "_http._tcp.local.",
		Domain:   "local.",
		Host:     "host.local.",
		Port:     8080,
		Priority: 10,
		Weight:   20,
		IPs:      []net.IP{net.IPv4(1, 2, 3, 4)},
		Text:     []string{"key=val"},
	}

	copy := copyServiceInstanceInfo(original)

	// Verify all fields match.
	if copy.Name != original.Name || copy.Type != original.Type ||
		copy.Host != original.Host || copy.Port != original.Port ||
		copy.Priority != original.Priority || copy.Weight != original.Weight {
		t.Error("field values don't match")
	}

	// Verify deep copy — mutating copy should not affect original.
	copy.IPs[0] = net.IPv4(9, 9, 9, 9)
	if original.IPs[0].Equal(net.IPv4(9, 9, 9, 9)) {
		t.Error("IPs slice should be independently copied")
	}

	copy.Text[0] = "modified"
	if original.Text[0] == "modified" {
		t.Error("Text slice should be independently copied")
	}
}

func TestCopyServiceInstanceInfoNil(t *testing.T) {
	result := copyServiceInstanceInfo(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestCopyServiceInstanceInfoEmpty(t *testing.T) {
	info := &ServiceInstanceInfo{Name: "test"}
	copy := copyServiceInstanceInfo(info)
	if copy.Name != "test" {
		t.Errorf("name: got %q, want %q", copy.Name, "test")
	}
	if copy.IPs != nil {
		t.Error("IPs should be nil for empty info")
	}
	if copy.Text != nil {
		t.Error("Text should be nil for empty info")
	}
}

// --- randIntNRange ---

func TestRandIntNRange(t *testing.T) {
	t.Run("positive n", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			val := randIntNRange(10)
			if val < 0 || val >= 10 {
				t.Errorf("randIntNRange(10): got %d, want [0, 10)", val)
			}
		}
	})

	t.Run("zero n", func(t *testing.T) {
		val := randIntNRange(0)
		if val != 0 {
			t.Errorf("randIntNRange(0): got %d, want 0", val)
		}
	})

	t.Run("negative n", func(t *testing.T) {
		val := randIntNRange(-5)
		if val != 0 {
			t.Errorf("randIntNRange(-5): got %d, want 0", val)
		}
	})
}

// ============================================================
// P1: dns_message.go header function tests
// ============================================================

func TestMessageIsQuery(t *testing.T) {
	query := &Message{Header: Header{Flags: 0}}
	if !query.IsQuery() {
		t.Error("Flags=0 should be a query")
	}

	response := &Message{Header: Header{Flags: flagResponse}}
	if response.IsQuery() {
		t.Error("flagResponse should not be a query")
	}
}

func TestMessageIsResponse(t *testing.T) {
	response := &Message{Header: Header{Flags: flagResponse}}
	if !response.IsResponse() {
		t.Error("flagResponse should be a response")
	}

	query := &Message{Header: Header{Flags: 0}}
	if query.IsResponse() {
		t.Error("Flags=0 should not be a response")
	}
}

func TestMessageIsProbe(t *testing.T) {
	probe := &Message{
		Header:      Header{Flags: 0},
		Authorities: []*ResourceRecord{{Name: "test.local.", Type: TypeA}},
	}
	if !probe.IsProbe() {
		t.Error("query with authorities should be a probe")
	}

	regular := &Message{Header: Header{Flags: 0}}
	if regular.IsProbe() {
		t.Error("query without authorities should not be a probe")
	}

	resp := &Message{
		Header:      Header{Flags: flagResponse},
		Authorities: []*ResourceRecord{{Name: "test.local.", Type: TypeA}},
	}
	if resp.IsProbe() {
		t.Error("response with authorities should not be a probe")
	}
}

func TestMessageIsValidmDNS(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		valid bool
	}{
		{"standard query", 0, true},
		{"standard response", flagResponse, true},
		{"response with rcode", flagResponse | 1, false}, // RCode=1
		{"query with opcode", opcodeQuery | (1 << 11), false}, // opcode=1
		{"authoritative response", flagResponse | flagAuthoritative, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{Header: Header{Flags: tt.flags}}
			if msg.IsValidmDNS() != tt.valid {
				t.Errorf("IsValidmDNS: got %v, want %v", msg.IsValidmDNS(), tt.valid)
			}
		})
	}
}

func TestMessageOpcode(t *testing.T) {
	msg := &Message{Header: Header{Flags: 0}}
	if msg.Opcode() != 0 {
		t.Errorf("default opcode: got %d, want 0", msg.Opcode())
	}

	// Set opcode to 1.
	msg.Flags = 1 << 11
	if msg.Opcode() != 1 {
		t.Errorf("opcode=1: got %d, want 1", msg.Opcode())
	}
}

func TestMessageRCode(t *testing.T) {
	msg := &Message{Header: Header{Flags: 0}}
	if msg.RCode() != 0 {
		t.Errorf("default rcode: got %d, want 0", msg.RCode())
	}

	msg.Flags = 3 // RCode=3 (NXDOMAIN)
	if msg.RCode() != 3 {
		t.Errorf("rcode=3: got %d, want 3", msg.RCode())
	}
}

// ============================================================
// Helpers
// ============================================================

func newTestServer() *Server {
	srv, _ := NewServer(DefaultConfig())
	return srv
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
