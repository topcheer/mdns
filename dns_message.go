package mdns

import (
	"encoding/binary"
	"fmt"
)

// DNS message header flags and masks (RFC 1035 §4.1.1 + RFC 6762 §18).
const (
	flagResponse      uint16 = 0x8000 // QR bit (1 = response)
	flagAuthoritative uint16 = 0x0400 // AA bit
	flagTruncation    uint16 = 0x0200 // TC bit

	opcodeMask  uint16 = 0x7800 // bits 11-14
	opcodeQuery uint16 = 0x0000 // standard query (opcode 0)

	rcodeMask   uint16 = 0x000F // bits 0-3
	rcodeNoErr  uint16 = 0x0000 // no error
)

// Opcode returns the 4-bit opcode field from the flags.
func (m *Message) Opcode() uint16 { return (m.Flags & opcodeMask) >> 11 }

// RCode returns the 4-bit response code from the flags.
func (m *Message) RCode() uint16 { return m.Flags & rcodeMask }

// IsValidmDNS checks basic mDNS compliance (RFC 6762 §18):
//   - opcode MUST be 0 (QUERY)
//   - RCode MUST be 0 (NOERROR)
//   - responses MUST NOT have a non-zero RCode
func (m *Message) IsValidmDNS() bool {
	if m.Opcode() != 0 {
		return false
	}
	if m.IsResponse() && m.RCode() != 0 {
		return false
	}
	return true
}

// Header is the 12-byte DNS message header (RFC 1035 §4.1.1).
type Header struct {
	ID         uint16
	Flags      uint16
	QDCount    uint16 // number of questions
	ANCount    uint16 // number of answer records
	NSCount    uint16 // number of authority records
	ARCount    uint16 // number of additional records
}

// Message is a complete DNS message (header + sections).
type Message struct {
	Header
	Questions   []*Question
	Answers     []*ResourceRecord
	Authorities []*ResourceRecord
	Additionals []*ResourceRecord
}

// IsQuery returns true if the message is a query (QR=0).
func (m *Message) IsQuery() bool { return m.Flags&flagResponse == 0 }

// IsResponse returns true if the message is a response (QR=1).
func (m *Message) IsResponse() bool { return m.Flags&flagResponse != 0 }

// IsTruncated returns true if the TC bit is set (RFC 6762 §7.2).
func (m *Message) IsTruncated() bool { return m.Flags&flagTruncation != 0 }

// IsProbe returns true if this query is a probe (has authority section records).
// Per RFC 6762 §8.2, a probe query contains proposed records in the Authority
// Section that answer the question in the Question Section.
func (m *Message) IsProbe() bool { return m.IsQuery() && len(m.Authorities) > 0 }

// Pack serializes the message to wire format.
func (m *Message) Pack() ([]byte, error) {
	buf := make([]byte, 0, 512)
	comp := make(map[string]int)

	// Header.
	buf = binary.BigEndian.AppendUint16(buf, m.ID)
	buf = binary.BigEndian.AppendUint16(buf, m.Flags)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.Questions)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.Answers)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.Authorities)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.Additionals)))

	// Sections.
	for _, q := range m.Questions {
		if err := q.pack(&buf, comp); err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Answers {
		if err := rr.pack(&buf, comp); err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Authorities {
		if err := rr.pack(&buf, comp); err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Additionals {
		if err := rr.pack(&buf, comp); err != nil {
			return nil, err
		}
	}

	// DNS messages (and thus mDNS) are limited to 9000 bytes (RFC 6762 §17).
	if len(buf) > 9000 {
		return nil, fmt.Errorf("mdns: message too large (%d bytes > 9000)", len(buf))
	}

	return buf, nil
}

// UnpackMessage parses a DNS message from wire format.
func UnpackMessage(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("mdns: message too short (%d bytes < 12)", len(data))
	}

	m := &Message{
		Header: Header{
			ID:      binary.BigEndian.Uint16(data[0:2]),
			Flags:   binary.BigEndian.Uint16(data[2:4]),
			QDCount: binary.BigEndian.Uint16(data[4:6]),
			ANCount: binary.BigEndian.Uint16(data[6:8]),
			NSCount: binary.BigEndian.Uint16(data[8:10]),
			ARCount: binary.BigEndian.Uint16(data[10:12]),
		},
	}

	offset := 12
	var err error

	// Questions.
	for i := 0; i < int(m.QDCount); i++ {
		q := &Question{}
		q.Name, offset, err = readName(data, offset)
		if err != nil {
			return nil, fmt.Errorf("mdns: failed to read question name: %w", err)
		}
		if offset+4 > len(data) {
			return nil, fmt.Errorf("mdns: truncated question record")
		}
		q.Type = binary.BigEndian.Uint16(data[offset:])
		q.Class = binary.BigEndian.Uint16(data[offset+2:])
		offset += 4
		m.Questions = append(m.Questions, q)
	}

	// Answers.
	m.Answers, offset, err = readRRs(data, offset, int(m.ANCount))
	if err != nil {
		return nil, fmt.Errorf("mdns: failed to read answer records: %w", err)
	}

	// Authorities.
	m.Authorities, offset, err = readRRs(data, offset, int(m.NSCount))
	if err != nil {
		return nil, fmt.Errorf("mdns: failed to read authority records: %w", err)
	}

	// Additionals.
	m.Additionals, offset, err = readRRs(data, offset, int(m.ARCount))
	if err != nil {
		return nil, fmt.Errorf("mdns: failed to read additional records: %w", err)
	}

	return m, nil
}

// readRRs reads count resource records from data starting at offset.
// Returns the parsed records and the new offset.
func readRRs(data []byte, offset, count int) ([]*ResourceRecord, int, error) {
	var rrs []*ResourceRecord
	var err error

	for i := 0; i < count; i++ {
		rr := &ResourceRecord{}

		// Name.
		rr.Name, offset, err = readName(data, offset)
		if err != nil {
			return nil, offset, fmt.Errorf("mdns: failed to read RR name: %w", err)
		}
		if offset+10 > len(data) {
			return nil, offset, fmt.Errorf("mdns: truncated RR header at record %d", i)
		}

		// Fixed header.
		rr.Type = binary.BigEndian.Uint16(data[offset:])
		classField := binary.BigEndian.Uint16(data[offset+2:])
		rr.CacheFlush = classField&cacheFlushBit != 0
		rr.Class = classField & ^cacheFlushBit
		rr.TTL = binary.BigEndian.Uint32(data[offset+4:])
		rdlen := int(binary.BigEndian.Uint16(data[offset+8:]))
		offset += 10

		// RDATA.
		if offset+rdlen > len(data) {
			return nil, offset, fmt.Errorf("mdns: truncated RDATA (need %d at %d)", rdlen, offset)
		}
		if err := rr.unpackRDATA(data, offset, rdlen); err != nil {
			return nil, offset, err
		}
		offset += rdlen

		rrs = append(rrs, rr)
	}

	return rrs, offset, nil
}

