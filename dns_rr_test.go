package mdns

import (
	"net"
	"testing"
)

// --- RRType ---

func TestRRType(t *testing.T) {
	tests := []struct {
		typ  uint16
		want string
	}{
		{TypeA, "A"},
		{TypeNS, "NS"},
		{TypeCNAME, "CNAME"},
		{TypeSOA, "SOA"},
		{TypePTR, "PTR"},
		{TypeTXT, "TXT"},
		{TypeAAAA, "AAAA"},
		{TypeSRV, "SRV"},
		{TypeOPT, "OPT"},
		{TypeNSEC, "NSEC"},
		{TypeAny, "ANY"},
		{999, "TYPE999"},
		{0, "TYPE0"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := RRType(tt.typ); got != tt.want {
				t.Errorf("RRType(%d): got %q, want %q", tt.typ, got, tt.want)
			}
		})
	}
}

// --- encodeTypeBitMaps / decodeTypeBitMaps round-trip ---

func TestEncodeDecodeTypeBitMapsRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		types []uint16
	}{
		{"single type window 0", []uint16{TypeA}},                          // type 1
		{"multiple types same window", []uint16{TypeA, TypePTR, TypeTXT}},   // 1, 12, 16
		{"types in high window", []uint16{TypeNSEC, TypeAny}},              // 47, 255
		{"sorted high-bit type", []uint16{TypeSRV, TypeAAAA, TypeA}},       // 33, 28, 1
		{"empty", []uint16{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf []byte
			if err := encodeTypeBitMaps(&buf, tt.types); err != nil {
				t.Fatalf("encodeTypeBitMaps: %v", err)
			}

			if len(tt.types) == 0 {
				if len(buf) != 0 {
					t.Errorf("expected empty output for empty input, got %d bytes", len(buf))
				}
				return
			}

			decoded, err := decodeTypeBitMaps(buf, 0, len(buf))
			if err != nil {
				t.Fatalf("decodeTypeBitMaps: %v", err)
			}

			// Compare as sets (order may differ).
			if !sameTypeSet(decoded, tt.types) {
				t.Errorf("round-trip mismatch: encoded %v → decoded %v", tt.types, decoded)
			}
		})
	}
}

// TestEncodeTypeBitMapsEmpty verifies that encoding an empty slice is a no-op.
func TestEncodeTypeBitMapsEmpty(t *testing.T) {
	var buf []byte
	err := encodeTypeBitMaps(&buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(buf) != 0 {
		t.Errorf("expected 0 bytes for empty types, got %d", len(buf))
	}
}

// TestEncodeTypeBitMapsBitPositions verifies that specific bits are set
// at the correct positions in the encoded bitmap.
func TestEncodeTypeBitMapsBitPositions(t *testing.T) {
	// Type A = 1: window 0, byte 0, bit position 1 (0-indexed from MSB).
	//   byte = 0b10000000 >> (1 % 8) = 0b01000000 = 0x40
	// Type PTR = 12: window 0, byte 1, bit position 4.
	//   byte = 0b10000000 >> (12 % 8) = 0b10000000 >> 4 = 0b00001000 = 0x08
	var buf []byte
	if err := encodeTypeBitMaps(&buf, []uint16{TypeA, TypePTR}); err != nil {
		t.Fatalf("encodeTypeBitMaps: %v", err)
	}

	// Expected layout: window(0) + bitmaplen(2) + byte0(0x40) + byte1(0x08)
	expected := []byte{0x00, 0x02, 0x40, 0x08}
	if len(buf) != len(expected) {
		t.Fatalf("encoded length: got %d, want %d", len(buf), len(expected))
	}
	for i, b := range expected {
		if buf[i] != b {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, buf[i], b)
		}
	}
}

// --- decodeTypeBitMaps error cases ---

func TestDecodeTypeBitMapsTruncated(t *testing.T) {
	// Only 1 byte — need at least 2 for block+length.
	_, err := decodeTypeBitMaps([]byte{0x00}, 0, 1)
	if err == nil {
		t.Error("expected error for truncated bitmap header")
	}
}

func TestDecodeTypeBitMapsExceedsMessage(t *testing.T) {
	// Block=0, length=5 but only 2 bytes of bitmap data available.
	msg := []byte{0x00, 0x05, 0x40, 0x00}
	_, err := decodeTypeBitMaps(msg, 0, len(msg))
	if err == nil {
		t.Error("expected error for bitmap length exceeding message")
	}
}

func TestDecodeTypeBitMapsEmpty(t *testing.T) {
	types, err := decodeTypeBitMaps(nil, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if types != nil {
		t.Errorf("expected nil for empty bitmap, got %v", types)
	}
}

func TestDecodeTypeBitMapsMultipleWindows(t *testing.T) {
	// Construct two-window bitmap:
	//   window 0: types [A(1), TXT(16)]
	//   window 1: type [256 + 0 = 256]
	//   window 0: block=0, len=3, bytes=[0x40, 0x00, 0x01]
	//     A=1 → byte 0 bit 1 → 0x40
	//     TXT=16 → byte 2 bit 0 → 0x80
	//   wait, TXT=16: bit=16, byte=16/8=2, bit_pos=16%8=0 → 0x80 >> 0 = 0x80
	//   So window 0 bytes = [0x40, 0x00, 0x80], len=3
	//   window 1: type 256: block=1, bit=0, byte 0 bit 0 → 0x80, len=1
	msg := []byte{
		0x00, 0x03, 0x40, 0x00, 0x80, // window 0: A + TXT
		0x01, 0x01, 0x80,             // window 1: type 256
	}
	types, err := decodeTypeBitMaps(msg, 0, len(msg))
	if err != nil {
		t.Fatalf("decodeTypeBitMaps: %v", err)
	}

	expected := []uint16{TypeA, TypeTXT, 256}
	if !sameTypeSet(types, expected) {
		t.Errorf("decoded types: got %v, want %v", types, expected)
	}
}

// --- ResourceRecord.String ---

func TestRRString(t *testing.T) {
	tests := []struct {
		name string
		rr   *ResourceRecord
		want string
	}{
		{
			"A record",
			&ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, IP: net.IPv4(10, 0, 0, 1)},
			"host.local. A 10.0.0.1",
		},
		{
			"AAAA record",
			&ResourceRecord{Name: "host.local.", Type: TypeAAAA, Class: ClassIN, TTL: 300, IP: net.ParseIP("fe80::1")},
			"host.local. AAAA fe80::1",
		},
		{
			"A record with cache-flush",
			&ResourceRecord{Name: "host.local.", Type: TypeA, Class: ClassIN, TTL: 300, CacheFlush: true, IP: net.IPv4(10, 0, 0, 1)},
			"host.local. A 10.0.0.1 (flush)",
		},
		{
			"PTR record",
			&ResourceRecord{Name: "_tcp.local.", Type: TypePTR, Class: ClassIN, TTL: 300, Target: "inst._tcp.local."},
			"_tcp.local. PTR inst._tcp.local.",
		},
		{
			"SRV record",
			&ResourceRecord{Name: "svc._tcp.local.", Type: TypeSRV, Class: ClassIN, TTL: 300, Priority: 10, Weight: 5, Port: 8080, Target: "host.local."},
			"svc._tcp.local. SRV pri=10 wt=5 port=8080 target=host.local.",
		},
		{
			"TXT record",
			&ResourceRecord{Name: "svc.local.", Type: TypeTXT, Class: ClassIN, TTL: 300, Text: []string{"k=v", "a=b"}},
			"svc.local. TXT k=v, a=b",
		},
		{
			"unknown type",
			&ResourceRecord{Name: "x.local.", Type: 999, Class: ClassIN, TTL: 300, RawData: []byte{0xAB, 0xCD}},
			"x.local. TYPE999 (2 bytes)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rr.String()
			if got != tt.want {
				t.Errorf("String():\n  got:  %q\n  want: %q", got, tt.want)
			}
		})
	}
}

func TestRRStringNSEC(t *testing.T) {
	rr := &ResourceRecord{
		Name:       "host.local.",
		Type:       TypeNSEC,
		Class:      ClassIN,
		TTL:        300,
		NextDomain: "next.local.",
		TypeBitMaps: []uint16{TypeA, TypeSRV},
	}
	got := rr.String()
	// NSEC string format: "name NSEC next=domain types=[A, SRV]"
	// We check key components since ordering of TypeBitMaps is preserved.
	if !contains(got, "NSEC") {
		t.Errorf("NSEC String missing 'NSEC': %q", got)
	}
	if !contains(got, "next=next.local.") {
		t.Errorf("NSEC String missing next domain: %q", got)
	}
	if !contains(got, "A") {
		t.Errorf("NSEC String missing type A: %q", got)
	}
}

// --- NSEC pack/unpack round-trip via full message ---

func TestNSECPackUnpackRoundTrip(t *testing.T) {
	original := &ResourceRecord{
		Name:       "host.local.",
		Type:       TypeNSEC,
		Class:      ClassIN,
		TTL:        120,
		NextDomain: "next.local.",
		TypeBitMaps: []uint16{TypeA, TypeAAAA, TypeSRV, TypeTXT},
	}

	// Pack into a message.
	msg := &Message{
		Header: Header{ANCount: 1},
		Answers: []*ResourceRecord{original},
	}
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("UnpackMessage: %v", err)
	}

	if len(decoded.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(decoded.Answers))
	}
	rr := decoded.Answers[0]
	if rr.Type != TypeNSEC {
		t.Fatalf("type: got %d, want NSEC(%d)", rr.Type, TypeNSEC)
	}
	if rr.NextDomain != "next.local." {
		t.Errorf("NextDomain: got %q, want %q", rr.NextDomain, "next.local.")
	}
	if !sameTypeSet(rr.TypeBitMaps, original.TypeBitMaps) {
		t.Errorf("TypeBitMaps: got %v, want %v", rr.TypeBitMaps, original.TypeBitMaps)
	}
}

// --- fullClass ---

func TestFullClass(t *testing.T) {
	rr := &ResourceRecord{Class: ClassIN}
	if got := rr.fullClass(); got != ClassIN {
		t.Errorf("fullClass without flush: got %d, want %d", got, ClassIN)
	}

	rr.CacheFlush = true
	if got := rr.fullClass(); got != ClassIN|cacheFlushBit {
		t.Errorf("fullClass with flush: got 0x%04x, want 0x%04x", got, ClassIN|cacheFlushBit)
	}
}

// --- helpers ---

func sameTypeSet(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[uint16]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
