package mdns

import (
	"net"
	"testing"
	"time"
)

// --- RemoveName ---

func TestCacheRemoveName(t *testing.T) {
	c := NewCache()

	// Insert records with the same name but different types.
	c.Upsert(&ResourceRecord{Name: "multi.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)
	c.Upsert(&ResourceRecord{Name: "multi.local.", Type: TypeAAAA, Class: ClassIN, TTL: 300, IP: net.ParseIP("fe80::1")}, nil)
	c.Upsert(&ResourceRecord{Name: "other.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 2)}, nil)

	c.RemoveName("multi.local.")

	if got := len(c.Lookup(rrKey("multi.local.", TypeA))); got != 0 {
		t.Errorf("RemoveName: expected 0 A records, got %d", got)
	}
	if got := len(c.Lookup(rrKey("multi.local.", TypeAAAA))); got != 0 {
		t.Errorf("RemoveName: expected 0 AAAA records, got %d", got)
	}
	// other.local. should be untouched.
	if got := len(c.Lookup(rrKey("other.local.", TypeA))); got != 1 {
		t.Errorf("RemoveName: expected other.local. A intact, got %d records", got)
	}
}

func TestCacheRemoveNameCaseInsensitive(t *testing.T) {
	c := NewCache()
	c.Upsert(&ResourceRecord{Name: "Host.Local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)

	c.RemoveName("host.local.")

	if got := len(c.Lookup(rrKey("host.local.", TypeA))); got != 0 {
		t.Errorf("RemoveName case-insensitive: expected 0 records, got %d", got)
	}
}

func TestCacheRemoveNameNonExistent(t *testing.T) {
	c := NewCache()
	c.Upsert(&ResourceRecord{Name: "keep.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)

	// Removing a name that doesn't exist should be a no-op, not panic.
	c.RemoveName("absent.local.")

	if got := len(c.Lookup(rrKey("keep.local.", TypeA))); got != 1 {
		t.Errorf("RemoveName non-existent: expected keep.local. intact, got %d", got)
	}
}

// --- HasValidRecord ---

func TestCacheHasValidRecord(t *testing.T) {
	c := NewCache()
	key := rrKey("valid.local.", TypeA)

	if c.HasValidRecord(key) {
		t.Error("HasValidRecord: expected false for empty cache")
	}

	c.Upsert(&ResourceRecord{Name: "valid.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)

	if !c.HasValidRecord(key) {
		t.Error("HasValidRecord: expected true after insert")
	}
}

func TestCacheHasValidRecordExpired(t *testing.T) {
	c := NewCache()
	key := rrKey("expired.local.", TypeA)

	c.Upsert(&ResourceRecord{Name: "expired.local.", Type: TypeA, Class: ClassIN, TTL: 0, IP: net.IPv4(10, 0, 0, 1)}, nil)
	time.Sleep(5 * time.Millisecond)

	if c.HasValidRecord(key) {
		t.Error("HasValidRecord: expected false for expired record")
	}
}

func TestCacheHasValidRecordWrongKey(t *testing.T) {
	c := NewCache()
	c.Upsert(&ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)

	// Query for a different type — should return false.
	key := rrKey("host.local.", TypeAAAA)
	if c.HasValidRecord(key) {
		t.Error("HasValidRecord: expected false for absent type")
	}
}

// --- RecordRemainingTTL ---

func TestCacheRecordRemainingTTL(t *testing.T) {
	c := NewCache()
	key := rrKey("ttl.local.", TypeA)

	c.Upsert(&ResourceRecord{Name: "ttl.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)

	remaining := c.RecordRemainingTTL(key)
	if remaining == 0 {
		t.Error("RecordRemainingTTL: expected non-zero remaining")
	}
	if remaining > 300 {
		t.Errorf("RecordRemainingTTL: remaining %d should not exceed original 300", remaining)
	}
}

func TestCacheRecordRemainingTTLAbsent(t *testing.T) {
	c := NewCache()
	key := rrKey("absent.local.", TypeA)

	if got := c.RecordRemainingTTL(key); got != 0 {
		t.Errorf("RecordRemainingTTL: expected 0 for absent record, got %d", got)
	}
}

// --- RecordOriginalTTL ---

func TestCacheRecordOriginalTTL(t *testing.T) {
	c := NewCache()
	key := rrKey("orig.local.", TypeA)

	c.Upsert(&ResourceRecord{Name: "orig.local.", Type: TypeA, Class: ClassIN, TTL: 4500, IP: net.IPv4(10, 0, 0, 1)}, nil)

	if got := c.RecordOriginalTTL(key); got != 4500 {
		t.Errorf("RecordOriginalTTL: got %d, want 4500", got)
	}
}

func TestCacheRecordOriginalTTLAbsent(t *testing.T) {
	c := NewCache()
	key := rrKey("absent.local.", TypeA)

	if got := c.RecordOriginalTTL(key); got != 0 {
		t.Errorf("RecordOriginalTTL: expected 0 for absent record, got %d", got)
	}
}

// --- AllRecords ---

func TestCacheAllRecords(t *testing.T) {
	c := NewCache()

	c.Upsert(&ResourceRecord{Name: "a.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)
	c.Upsert(&ResourceRecord{Name: "b.local.", Type: TypePTR, Class: ClassIN, TTL: 300, Target: "srv.local."}, nil)
	c.Upsert(&ResourceRecord{Name: "c.local.", Type: TypeSRV, Class: ClassIN, TTL: 300, Port: 80, Target: "host.local."}, nil)

	all := c.AllRecords()
	if len(all) != 3 {
		t.Errorf("AllRecords: expected 3 records, got %d", len(all))
	}
}

func TestCacheAllRecordsEmpty(t *testing.T) {
	c := NewCache()
	all := c.AllRecords()
	if all != nil {
		t.Errorf("AllRecords: expected nil for empty cache, got %v", all)
	}
}

func TestCacheAllRecordsExcludesExpired(t *testing.T) {
	c := NewCache()

	c.Upsert(&ResourceRecord{Name: "live.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)
	c.Upsert(&ResourceRecord{Name: "dead.local.", Type: TypeA, Class: ClassIN, TTL: 0, IP: net.IPv4(10, 0, 0, 2)}, nil)

	time.Sleep(5 * time.Millisecond)

	all := c.AllRecords()
	if len(all) != 1 {
		t.Errorf("AllRecords: expected 1 non-expired record, got %d", len(all))
	}
	if !all[0].IP.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("AllRecords: expected live.local. record, got IP %s", all[0].IP)
	}
}

// --- KnownAnswers ---

func TestCacheKnownAnswers(t *testing.T) {
	c := NewCache()
	c.Upsert(&ResourceRecord{Name: "svc.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)

	// Fresh record: remaining TTL should be > 50% of original → included.
	ka := c.KnownAnswers("svc.local.", TypeA)
	if len(ka) != 1 {
		t.Errorf("KnownAnswers: expected 1 record for fresh entry, got %d", len(ka))
	}
}

func TestCacheKnownAnswersEmpty(t *testing.T) {
	c := NewCache()
	ka := c.KnownAnswers("absent.local.", TypeA)
	if len(ka) != 0 {
		t.Errorf("KnownAnswers: expected 0 for empty cache, got %d", len(ka))
	}
}

func TestCacheKnownAnswersWrongType(t *testing.T) {
	c := NewCache()
	c.Upsert(&ResourceRecord{Name: "svc.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)

	ka := c.KnownAnswers("svc.local.", TypeAAAA)
	if len(ka) != 0 {
		t.Errorf("KnownAnswers: expected 0 for wrong type, got %d", len(ka))
	}
}

// --- sameIP ---

func TestSameIP(t *testing.T) {
	tests := []struct {
		name string
		a, b net.IP
		want bool
	}{
		{"both nil", nil, nil, true},
		{"first nil", nil, net.IPv4(1, 2, 3, 4), false},
		{"second nil", net.IPv4(1, 2, 3, 4), nil, false},
		{"equal IPv4", net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1), true},
		{"different IPv4", net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), false},
		{
			"equal IPv6",
			net.ParseIP("fe80::1"),
			net.ParseIP("fe80::1"),
			true,
		},
		{
			"v4 vs v6",
			net.IPv4(10, 0, 0, 1),
			net.ParseIP("::1"),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameIP(tt.a, tt.b); got != tt.want {
				t.Errorf("sameIP: got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- matchDomain ---

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		suffix string
		want   bool
	}{
		{"exact match", "host.local.", ".local.", true},
		{"case-insensitive", "Host.LOCAL.", ".local.", true},
		{"suffix mismatch", "host.remote.", ".local.", false},
		{"empty domain", "", ".local.", false},
		{"empty suffix", "host.local.", "", true},
		{"service type match", "_http._tcp.local.", "._tcp.local.", true},
		{"subdomain match", "a.b.local.", ".local.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchDomain(tt.domain, tt.suffix); got != tt.want {
				t.Errorf("matchDomain(%q, %q): got %v, want %v", tt.domain, tt.suffix, got, tt.want)
			}
		})
	}
}
