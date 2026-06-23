package mdns

import (
	"errors"
	"fmt"
	"strings"
)

// DNS name compression pointer mask.
const pointerMask = 0xC0 // top two bits set => compression pointer

// Errors.
var (
	ErrNameTooLong      = errors.New("mdns: domain name too long (>255 bytes)")
	ErrLabelTooLong     = errors.New("mdns: label too long (>63 bytes)")
	ErrInvalidPointer   = errors.New("mdns: invalid compression pointer")
	ErrPointerLoop      = errors.New("mdns: compression pointer loop detected")
	ErrTruncatedName    = errors.New("mdns: domain name is truncated")
)

// readName reads a DNS name from msg starting at offset.
// It follows compression pointers as needed.
// Returns the name (in presentation format: "example.local."),
// the offset in msg right after the name field (NOT following pointers),
// and any error.
func readName(msg []byte, offset int) (string, int, error) {
	if offset >= len(msg) {
		return "", 0, ErrTruncatedName
	}

	var labels []string
	originalOffset := offset
	pos := offset
	jumped := false
	jumps := 0

	for {
		if pos >= len(msg) {
			return "", 0, ErrTruncatedName
		}

		length := int(msg[pos])
		if length == 0 {
			pos++
			break
		}

		// Check if this is a compression pointer (top 2 bits set).
		if length&pointerMask == pointerMask {
			if pos+1 >= len(msg) {
				return "", 0, ErrTruncatedName
			}
			pointer := int(msg[pos]&^pointerMask)<<8 | int(msg[pos+1])
			if pointer >= len(msg) {
				return "", 0, ErrInvalidPointer
			}
			if !jumped {
				originalOffset = pos + 2 // the offset after this name field
			}
			jumped = true
			jumps++
			if jumps > 128 {
				return "", 0, ErrPointerLoop
			}
			pos = pointer
			continue
		}

		// Regular label.
		if length > 63 {
			return "", 0, fmt.Errorf("mdns: label length %d exceeds 63", length)
		}

		pos++
		if pos+length > len(msg) {
			return "", 0, ErrTruncatedName
		}

		labels = append(labels, string(msg[pos:pos+length]))
		pos += length
	}

	if !jumped {
		originalOffset = pos
	}

	var name string
	if len(labels) == 0 {
		name = "."
	} else {
		name = strings.Join(labels, ".") + "."
	}

	return name, originalOffset, nil
}

// writeName writes a DNS name to buf, using compression where possible.
// compression maps name suffixes to their byte offsets in buf.
// Returns an error if the name is too long.
func writeName(buf *[]byte, name string, compression map[string]int) error {
	// Normalize: ensure trailing dot, treat "." as root.
	name = normalizeName(name)
	if name == "." {
		*buf = append(*buf, 0)
		return nil
	}

	// Strip trailing dot for processing, keep as suffixes.
	stripped := strings.TrimSuffix(name, ".")

	for stripped != "" {
		// Check if this suffix is already in the message.
		suffix := stripped + "."
		if offset, ok := compression[suffix]; ok {
			if offset > 0x3FFF {
				return ErrInvalidPointer
			}
			*buf = append(*buf, byte(offset>>8|pointerMask), byte(offset&0xFF))
			return nil
		}

		// Get the next label.
		dot := strings.IndexByte(stripped, '.')
		var label string
		var rest string
		if dot < 0 {
			label = stripped
			rest = ""
		} else {
			label = stripped[:dot]
			rest = stripped[dot+1:]
		}

		if len(label) > 63 {
			return fmt.Errorf("%w: %d", ErrLabelTooLong, len(label))
		}

		// Record the offset of this suffix for future compression.
		offset := len(*buf)
		if offset <= 0x3FFF {
			compression[suffix] = offset
		}

		*buf = append(*buf, byte(len(label)))
		*buf = append(*buf, label...)

		if rest == "" {
			*buf = append(*buf, 0)
			break
		}
		stripped = rest
	}

	return nil
}

// normalizeName ensures a trailing dot on a DNS name.
func normalizeName(name string) string {
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// lowerName returns a lowercased version of a DNS name for case-insensitive comparison.
func lowerName(name string) string {
	return strings.ToLower(name)
}
