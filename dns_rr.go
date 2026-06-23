package mdns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// RR type constants (DNS record types).
const (
	TypeA      uint16 = 1    // IPv4 address
	TypeNS     uint16 = 2    // Name Server
	TypeCNAME  uint16 = 5    // Canonical Name
	TypeSOA    uint16 = 6    // Start of Authority
	TypePTR    uint16 = 12   // Domain Name Pointer
	TypeTXT    uint16 = 16   // Text
	TypeAAAA   uint16 = 28   // IPv6 address
	TypeSRV    uint16 = 33   // Service
	TypeOPT    uint16 = 41   // EDNS0 option
	TypeNSEC   uint16 = 47   // Next Secure (Negative cache)
	TypeAny    uint16 = 255  // Any / all records
)

// RR class constants.
const (
	ClassIN    uint16 = 1    // Internet
	ClassNone  uint16 = 254  // None (RFC 4034)
	ClassAny   uint16 = 255  // Any
)

// The cache-flush bit is the top bit of the class field (RFC 6762 §10.2).
const cacheFlushBit uint16 = 0x8000

// RRType returns a human-readable string for common record types.
func RRType(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeNSEC:
		return "NSEC"
	case TypeAny:
		return "ANY"
	default:
		return "TYPE" + strconv.Itoa(int(t))
	}
}

// Question is a DNS question entry.
type Question struct {
	Name  string // e.g. "_http._tcp.local."
	Type  uint16
	Class uint16 // without cache-flush bit (always 0 in questions)
}

// pack writes a question to buf.
func (q *Question) pack(buf *[]byte, comp map[string]int) error {
	if err := writeName(buf, q.Name, comp); err != nil {
		return err
	}
	*buf = binary.BigEndian.AppendUint16(*buf, q.Type)
	*buf = binary.BigEndian.AppendUint16(*buf, q.Class)
	return nil
}

// ResourceRecord is a DNS resource record with type-specific RDATA.
type ResourceRecord struct {
	Name       string
	Type       uint16
	Class      uint16 // stored without cache-flush bit
	TTL        uint32
	CacheFlush bool // whether the cache-flush bit is set (for mDNS)

	// Type-specific data — only the relevant fields are populated.
	IP          net.IP     // A / AAAA
	Target      string     // PTR / CNAME / NS  (target domain name)
	Priority    uint16     // SRV
	Weight      uint16     // SRV
	Port        uint16     // SRV
	Text        []string   // TXT
	NextDomain  string     // NSEC
	TypeBitMaps []uint16   // NSEC
	RawData     []byte     // for unrecognised types
}

// fullClass returns the class field value with the cache-flush bit set if applicable.
func (rr *ResourceRecord) fullClass() uint16 {
	c := rr.Class
	if rr.CacheFlush {
		c |= cacheFlushBit
	}
	return c
}

// packRDATA writes the type-specific RDATA to buf.
// It records the RDATA length position, writes the data, then patches the length.
func (rr *ResourceRecord) pack(buf *[]byte, comp map[string]int) error {
	// Write fixed header.
	if err := writeName(buf, rr.Name, comp); err != nil {
		return err
	}
	*buf = binary.BigEndian.AppendUint16(*buf, rr.Type)
	*buf = binary.BigEndian.AppendUint16(*buf, rr.fullClass())
	*buf = binary.BigEndian.AppendUint32(*buf, rr.TTL)

	// Reserve 2 bytes for RDLENGTH; remember position.
	rdLenPos := len(*buf)
	*buf = append(*buf, 0, 0) // placeholder
	rdStart := len(*buf)

	switch rr.Type {
	case TypeA:
		ip4 := rr.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("mdns: A record requires a 4-byte IPv4 address, got %v", rr.IP)
		}
		*buf = append(*buf, ip4...)

	case TypeAAAA:
		ip6 := rr.IP.To16()
		if ip6 == nil {
			return fmt.Errorf("mdns: AAAA record requires a 16-byte IPv6 address, got %v", rr.IP)
		}
		*buf = append(*buf, ip6...)

	case TypePTR, TypeCNAME, TypeNS:
		if err := writeName(buf, rr.Target, comp); err != nil {
			return err
		}

	case TypeSRV:
		*buf = binary.BigEndian.AppendUint16(*buf, rr.Priority)
		*buf = binary.BigEndian.AppendUint16(*buf, rr.Weight)
		*buf = binary.BigEndian.AppendUint16(*buf, rr.Port)
		if err := writeName(buf, rr.Target, comp); err != nil {
			return err
		}

	case TypeTXT:
		if len(rr.Text) == 0 {
			// Empty TXT = single zero-length string.
			*buf = append(*buf, 0)
		} else {
			for _, s := range rr.Text {
				if len(s) > 255 {
					return fmt.Errorf("mdns: TXT string too long (%d bytes)", len(s))
				}
				*buf = append(*buf, byte(len(s)))
				*buf = append(*buf, s...)
			}
		}

	case TypeNSEC:
		if err := writeName(buf, rr.NextDomain, comp); err != nil {
			return err
		}
		// Encode type bit maps (RFC 4034 §4.1.2).
		if err := encodeTypeBitMaps(buf, rr.TypeBitMaps); err != nil {
			return err
		}

	default:
		*buf = append(*buf, rr.RawData...)
	}

	// Patch RDLENGTH.
	rdLen := len(*buf) - rdStart
	binary.BigEndian.PutUint16((*buf)[rdLenPos:], uint16(rdLen))
	return nil
}

// unpackRDATA reads the RDATA for this RR from msg at the given offset
// (right after the fixed header), with the given rdlength.
func (rr *ResourceRecord) unpackRDATA(msg []byte, offset, rdlen int) error {
	end := offset + rdlen
	if end > len(msg) {
		return fmt.Errorf("mdns: RDATA truncated (need %d bytes at offset %d)", rdlen, offset)
	}

	switch rr.Type {
	case TypeA:
		if rdlen != 4 {
			return fmt.Errorf("mdns: A record has invalid RDLENGTH %d", rdlen)
		}
		rr.IP = net.IP(append([]byte(nil), msg[offset:offset+4]...))

	case TypeAAAA:
		if rdlen != 16 {
			return fmt.Errorf("mdns: AAAA record has invalid RDLENGTH %d", rdlen)
		}
		rr.IP = net.IP(append([]byte(nil), msg[offset:offset+16]...))

	case TypePTR, TypeCNAME, TypeNS:
		name, _, err := readName(msg, offset)
		if err != nil {
			return err
		}
		rr.Target = name

	case TypeSRV:
		if rdlen < 7 {
			return fmt.Errorf("mdns: SRV record too short (%d bytes)", rdlen)
		}
		rr.Priority = binary.BigEndian.Uint16(msg[offset:])
		rr.Weight = binary.BigEndian.Uint16(msg[offset+2:])
		rr.Port = binary.BigEndian.Uint16(msg[offset+4:])
		target, _, err := readName(msg, offset+6)
		if err != nil {
			return err
		}
		rr.Target = target

	case TypeTXT:
		rr.Text = nil
		pos := offset
		for pos < end {
			l := int(msg[pos])
			pos++
			if pos+l > end {
				return fmt.Errorf("mdns: TXT record truncated")
			}
			rr.Text = append(rr.Text, string(msg[pos:pos+l]))
			pos += l
		}
		if rr.Text == nil {
			rr.Text = []string{}
		}

	case TypeNSEC:
		nextDomain, nextOffset, err := readName(msg, offset)
		if err != nil {
			return err
		}
		rr.NextDomain = nextDomain
		rr.TypeBitMaps, err = decodeTypeBitMaps(msg, nextOffset, end)
		if err != nil {
			return err
		}

	default:
		rr.RawData = append([]byte(nil), msg[offset:end]...)
	}

	return nil
}

// encodeTypeBitMaps encodes a sorted list of RR types as DNSSEC type bit maps
// (RFC 4034 §4.1.2).  Each block: window block (1 byte) + bitmap length (1 byte) + bitmap.
func encodeTypeBitMaps(buf *[]byte, types []uint16) error {
	if len(types) == 0 {
		return nil
	}

	// Group types by window block (type / 256).
	blocks := make(map[uint8][]uint8)
	for _, t := range types {
		block := uint8(t >> 8)
		bit := uint8(t & 0xFF)
		bits := blocks[block]
		needed := int(bit/8) + 1
		if len(bits) < needed {
			extra := make([]uint8, needed-len(bits))
			bits = append(bits, extra...)
		}
		bits[bit/8] |= 0x80 >> (bit % 8)
		blocks[block] = bits
	}

	// Write blocks in ascending window order.
	for block := uint8(0); block < 255; block++ {
		bits, ok := blocks[block]
		if !ok {
			continue
		}
		*buf = append(*buf, block)
		*buf = append(*buf, byte(len(bits)))
		*buf = append(*buf, bits...)
	}
	return nil
}

// decodeTypeBitMaps decodes the type bit maps portion of an NSEC record.
func decodeTypeBitMaps(msg []byte, offset, end int) ([]uint16, error) {
	var types []uint16
	pos := offset
	for pos < end {
		if pos+2 > end {
			return nil, fmt.Errorf("mdns: NSEC type bitmap truncated")
		}
		block := msg[pos]
		bitmapLen := int(msg[pos+1])
		pos += 2
		if pos+bitmapLen > end {
			return nil, fmt.Errorf("mdns: NSEC type bitmap exceeds message")
		}
		for i := 0; i < bitmapLen; i++ {
			if msg[pos+i] == 0 {
				continue
			}
			for bit := 0; bit < 8; bit++ {
				if msg[pos+i]&(0x80>>bit) != 0 {
					types = append(types, uint16(block)*256+uint16(i*8+bit))
				}
			}
		}
		pos += bitmapLen
	}
	return types, nil
}

// String returns a human-readable representation of the RR.
func (rr *ResourceRecord) String() string {
	cf := ""
	if rr.CacheFlush {
		cf = " (flush)"
	}
	_ = cf

	switch rr.Type {
	case TypeA, TypeAAAA:
		return fmt.Sprintf("%s %s %s%s", normalizeName(rr.Name), RRType(rr.Type), rr.IP.String(), cf)
	case TypePTR, TypeCNAME, TypeNS:
		return fmt.Sprintf("%s %s %s%s", normalizeName(rr.Name), RRType(rr.Type), rr.Target, cf)
	case TypeSRV:
		return fmt.Sprintf("%s SRV pri=%d wt=%d port=%d target=%s", normalizeName(rr.Name), rr.Priority, rr.Weight, rr.Port, rr.Target)
	case TypeTXT:
		return fmt.Sprintf("%s TXT %s", normalizeName(rr.Name), strings.Join(rr.Text, ", "))
	case TypeNSEC:
		typeStrs := make([]string, len(rr.TypeBitMaps))
		for i, t := range rr.TypeBitMaps {
			typeStrs[i] = RRType(t)
		}
		return fmt.Sprintf("%s NSEC next=%s types=[%s]", normalizeName(rr.Name), rr.NextDomain, strings.Join(typeStrs, ", "))
	default:
		return fmt.Sprintf("%s TYPE%d (%d bytes)", normalizeName(rr.Name), rr.Type, len(rr.RawData))
	}
}
