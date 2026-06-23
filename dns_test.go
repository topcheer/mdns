package mdns

import (
	"net"
	"testing"
)

func TestNameEncoding(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"example.local.", "example.local."},
		{"_http._tcp.local.", "_http._tcp.local."},
		{".", "."},
		{"single", "single."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf []byte
			comp := make(map[string]int)
			if err := writeName(&buf, tt.name, comp); err != nil {
				t.Fatalf("writeName failed: %v", err)
			}
			got, _, err := readName(buf, 0)
			if err != nil {
				t.Fatalf("readName failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("roundtrip: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNameCompression(t *testing.T) {
	var buf []byte
	comp := make(map[string]int)

	// Write a name.
	if err := writeName(&buf, "foo.example.local.", comp); err != nil {
		t.Fatal(err)
	}
	firstLen := len(buf)

	// Write another name that shares a suffix.
	if err := writeName(&buf, "bar.example.local.", comp); err != nil {
		t.Fatal(err)
	}
	totalLen := len(buf)

	// The second name should use compression for "example.local.".
	// "bar" label (5 bytes) + pointer (2 bytes) = 7 bytes, vs writing full name.
	if totalLen-firstLen >= firstLen {
		t.Errorf("compression not working: second name used %d bytes (first used %d)",
			totalLen-firstLen, firstLen)
	}

	// Verify both names can be read back correctly.
	name1, _, err := readName(buf, 0)
	if err != nil {
		t.Fatalf("readName 1: %v", err)
	}
	if name1 != "foo.example.local." {
		t.Errorf("name1: got %q, want %q", name1, "foo.example.local.")
	}

	name2, _, err := readName(buf, firstLen)
	if err != nil {
		t.Fatalf("readName 2: %v", err)
	}
	if name2 != "bar.example.local." {
		t.Errorf("name2: got %q, want %q", name2, "bar.example.local.")
	}
}

func TestLabelTooLong(t *testing.T) {
	longLabel := make([]byte, 70)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	name := string(longLabel) + ".local."

	var buf []byte
	comp := make(map[string]int)
	err := writeName(&buf, name, comp)
	if err == nil {
		t.Error("expected error for too-long label, got nil")
	}
}

func TestMessageRoundtrip(t *testing.T) {
	original := &Message{
		Header: Header{
			Flags:   flagResponse | flagAuthoritative,
			QDCount: 1,
			ANCount: 3,
		},
		Questions: []*Question{
			{Name: "_http._tcp.local.", Type: TypePTR, Class: ClassIN},
		},
		Answers: []*ResourceRecord{
			{
				Name:  "_http._tcp.local.",
				Type:  TypePTR,
				Class: ClassIN,
				TTL:   4500,
				Target: "My Server._http._tcp.local.",
			},
			{
				Name:       "My Server._http._tcp.local.",
				Type:       TypeSRV,
				Class:      ClassIN,
				TTL:        120,
				CacheFlush: true,
				Priority:   0,
				Weight:     0,
				Port:       8080,
				Target:     "myhost.local.",
			},
			{
				Name:       "myhost.local.",
				Type:       TypeA,
				Class:      ClassIN,
				TTL:        120,
				CacheFlush: true,
				IP:         net.IPv4(192, 168, 1, 100),
			},
		},
	}

	data, err := original.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if len(decoded.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(decoded.Questions))
	}
	if decoded.Questions[0].Name != "_http._tcp.local." {
		t.Errorf("question name: got %q", decoded.Questions[0].Name)
	}

	if len(decoded.Answers) != 3 {
		t.Fatalf("expected 3 answers, got %d", len(decoded.Answers))
	}

	// Check PTR.
	ptr := decoded.Answers[0]
	if ptr.Type != TypePTR || ptr.Target != "My Server._http._tcp.local." {
		t.Errorf("PTR record mismatch: %+v", ptr)
	}

	// Check SRV.
	srv := decoded.Answers[1]
	if srv.Type != TypeSRV || srv.Port != 8080 || srv.Target != "myhost.local." {
		t.Errorf("SRV record mismatch: %+v", srv)
	}
	if !srv.CacheFlush {
		t.Error("SRV should have cache-flush bit set")
	}

	// Check A.
	a := decoded.Answers[2]
	if a.Type != TypeA || !a.IP.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("A record mismatch: %+v", a)
	}
}

func TestTXTRecordRoundtrip(t *testing.T) {
	original := &ResourceRecord{
		Name: "test.local.",
		Type: TypeTXT,
		Class: ClassIN,
		TTL:  4500,
		Text: []string{"key1=val1", "key2=val2", "path=/api"},
	}

	msg := &Message{
		Header:   Header{ANCount: 1},
		Answers:  []*ResourceRecord{original},
	}

	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if len(decoded.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(decoded.Answers))
	}

	txt := decoded.Answers[0]
	if len(txt.Text) != 3 {
		t.Fatalf("expected 3 TXT entries, got %d", len(txt.Text))
	}
	for i, want := range original.Text {
		if txt.Text[i] != want {
			t.Errorf("TXT[%d]: got %q, want %q", i, txt.Text[i], want)
		}
	}
}

func TestAAAARecordRoundtrip(t *testing.T) {
	ip6 := net.ParseIP("fe80::1")
	original := &ResourceRecord{
		Name: "host.local.",
		Type: TypeAAAA,
		Class: ClassIN,
		TTL:  120,
		IP:   ip6,
	}

	msg := &Message{Answers: []*ResourceRecord{original}}

	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	a := decoded.Answers[0]
	if !a.IP.Equal(ip6) {
		t.Errorf("AAAA mismatch: got %s, want %s", a.IP, ip6)
	}
}

func TestEmptyTXTRecord(t *testing.T) {
	original := &ResourceRecord{
		Name: "test.local.",
		Type: TypeTXT,
		Class: ClassIN,
		TTL:  4500,
		Text: []string{},
	}

	msg := &Message{Answers: []*ResourceRecord{original}}

	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	// Per RFC, empty TXT record = single zero-length string [""].
	if len(decoded.Answers[0].Text) != 1 || decoded.Answers[0].Text[0] != "" {
		t.Errorf("expected [\"\"], got %v", decoded.Answers[0].Text)
	}
}

func TestMessageTooShort(t *testing.T) {
	_, err := UnpackMessage([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short message")
	}
}

func TestCacheFlushBit(t *testing.T) {
	rr := &ResourceRecord{
		Name:       "test.local.",
		Type:       TypeA,
		Class:      ClassIN,
		TTL:        120,
		CacheFlush: true,
		IP:         net.IPv4(10, 0, 0, 1),
	}

	msg := &Message{Answers: []*ResourceRecord{rr}}
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if !decoded.Answers[0].CacheFlush {
		t.Error("cache-flush bit not preserved")
	}
	if decoded.Answers[0].Class != ClassIN {
		t.Errorf("class: got %d, want %d", decoded.Answers[0].Class, ClassIN)
	}
}

func TestMultipleQuestions(t *testing.T) {
	msg := &Message{
		Header: Header{QDCount: 2},
		Questions: []*Question{
			{Name: "host.local.", Type: TypeA, Class: ClassIN},
			{Name: "host.local.", Type: TypeAAAA, Class: ClassIN},
		},
	}

	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	decoded, err := UnpackMessage(data)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if len(decoded.Questions) != 2 {
		t.Fatalf("expected 2 questions, got %d", len(decoded.Questions))
	}
}
