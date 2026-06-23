package mdns

import (
	"net"
	"testing"
	"time"
)

func TestCacheUpsertLookup(t *testing.T) {
	c := NewCache()

	rr := &ResourceRecord{
		Name: "host.local.",
		Type: TypeA,
		Class: ClassIN,
		TTL:  300,
		IP:   net.IPv4(192, 168, 1, 1),
	}

	c.Upsert(rr, nil)

	results := c.Lookup(rrKey("host.local.", TypeA))
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].IP.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("IP mismatch: got %s", results[0].IP)
	}
}

func TestCacheMultipleRecords(t *testing.T) {
	c := NewCache()

	rr1 := &ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}
	rr2 := &ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 2)}

	c.Upsert(rr1, nil)
	c.Upsert(rr2, nil)

	results := c.Lookup(rrKey("host.local.", TypeA))
	if len(results) != 2 {
		t.Fatalf("expected 2 records, got %d", len(results))
	}
}

func TestCacheFlush(t *testing.T) {
	c := NewCache()

	rr1 := &ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}
	rr2 := &ResourceRecord{
		Name:       "host.local.",
		Type:       TypeA,
		Class:      ClassIN,
		TTL:        300,
		CacheFlush: true,
		IP:         net.IPv4(10, 0, 0, 2),
	}

	c.Upsert(rr1, nil)
	c.Upsert(rr2, nil) // flush should remove rr1 (same RDATA type)

	results := c.Lookup(rrKey("host.local.", TypeA))
	if len(results) != 1 {
		t.Fatalf("expected 1 record after flush, got %d", len(results))
	}
	if !results[0].IP.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Errorf("wrong record after flush: %s", results[0].IP)
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache()

	rr := &ResourceRecord{
		Name: "expire.local.",
		Type: TypeA,
		Class: ClassIN,
		TTL:  0, // expires immediately
		IP:   net.IPv4(10, 0, 0, 1),
	}

	c.Upsert(rr, nil)

	// Wait a tiny bit for the record to expire.
	time.Sleep(10 * time.Millisecond)

	results := c.Lookup(rrKey("expire.local.", TypeA))
	if len(results) != 0 {
		t.Errorf("expected 0 records after expiry, got %d", len(results))
	}

	// Expire should clean up.
	removed := c.Expire()
	if removed == 0 {
		t.Error("expected Expire to remove at least 1 record")
	}
}

func TestCacheRemove(t *testing.T) {
	c := NewCache()

	rr := &ResourceRecord{Name: "gone.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}
	c.Upsert(rr, nil)

	c.Remove(rrKey("gone.local.", TypeA))

	results := c.Lookup(rrKey("gone.local.", TypeA))
	if len(results) != 0 {
		t.Errorf("expected 0 records after remove, got %d", len(results))
	}
}

func TestCacheLookupName(t *testing.T) {
	c := NewCache()

	c.Upsert(&ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)}, nil)
	c.Upsert(&ResourceRecord{Name: "host.local.", Type: TypeAAAA, Class: ClassIN, TTL: 300, IP: net.ParseIP("fe80::1")}, nil)

	results := c.LookupName("host.local.")
	if len(results) != 2 {
		t.Errorf("expected 2 records, got %d", len(results))
	}
}

func TestRecordsEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b *ResourceRecord
		want bool
	}{
		{
			"same A",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			true,
		},
		{
			"different IP",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 5)},
			false,
		},
		{
			"case-insensitive name",
			&ResourceRecord{Name: "Host.Local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "host.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			true,
		},
		{
			"same PTR",
			&ResourceRecord{Name: "_tcp.local.", Type: TypePTR, Target: "inst._tcp.local."},
			&ResourceRecord{Name: "_tcp.local.", Type: TypePTR, Target: "inst._tcp.local."},
			true,
		},
		{
			"different types",
			&ResourceRecord{Name: "h.local.", Type: TypeA, IP: net.IPv4(1, 2, 3, 4)},
			&ResourceRecord{Name: "h.local.", Type: TypeAAAA, IP: net.IPv4(1, 2, 3, 4)},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := recordsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("recordsEqual: got %v, want %v", got, tt.want)
			}
		})
	}
}
