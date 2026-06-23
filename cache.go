package mdns

import (
	"net"
	"strings"
	"sync"
	"time"
)

// CacheKey uniquely identifies a cached record by name + type.
type CacheKey struct {
	Name  string // lowercase
	Type  uint16
}

// rrKey creates a cache key for a resource record.
func rrKey(name string, rrType uint16) CacheKey {
	return CacheKey{Name: lowerName(normalizeName(name)), Type: rrType}
}

// cachedRecord is a cached resource record with metadata.
type cachedRecord struct {
	rr       *ResourceRecord
	expires  time.Time
	received time.Time
}

// Cache is a thread-safe DNS record cache with TTL-based expiry.
// It implements the caching behaviour described in RFC 6762 §5.2 and §10.
type Cache struct {
	mu      sync.RWMutex
	records map[CacheKey][]*cachedRecord // multiple records per key (e.g. multiple A records)
}

// NewCache creates a new empty cache.
func NewCache() *Cache {
	return &Cache{
		records: make(map[CacheKey][]*cachedRecord),
	}
}

// Upsert adds or updates a record in the cache.
// If cacheFlush is set (mDNS cache-flush bit), all existing records for the
// same name/type from a different source are removed (RFC 6762 §10.2).
// Returns true if the cache was modified.
func (c *Cache) Upsert(rr *ResourceRecord, from net.IP) bool {
	key := rrKey(rr.Name, rr.Type)
	now := time.Now()
	ttl := time.Duration(rr.TTL) * time.Second

	c.mu.Lock()
	defer c.mu.Unlock()

	existing := c.records[key]

	// If cache-flush bit is set, remove all existing records of this type
	// that came from a different source IP.  (RFC 6762 §10.2)
	// If cache-flush bit is set, remove all existing records of this type
	// for this name (RFC 6762 §10.2).  The authoritative source is updating
	// its records, so all old records are stale.
	if rr.CacheFlush {
		existing = nil
	}

	// Check if we already have an identical record (same RDATA).
	for _, cr := range existing {
		if recordsEqual(cr.rr, rr) {
			// Update TTL / refresh expiry.
			cr.rr.TTL = rr.TTL
			cr.expires = now.Add(ttl)
			cr.received = now
			return true
		}
	}

	// Add new record.
	existing = append(existing, &cachedRecord{
		rr:       rr,
		expires:  now.Add(ttl),
		received: now,
	})
	c.records[key] = existing
	return true
}

// Lookup returns all non-expired records matching the key.
func (c *Cache) Lookup(key CacheKey) []*ResourceRecord {
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*ResourceRecord
	for _, cr := range c.records[key] {
		if cr.expires.After(now) {
			result = append(result, cr.rr)
		}
	}
	return result
}

// LookupName returns all non-expired records for a given name (any type).
func (c *Cache) LookupName(name string) []*ResourceRecord {
	ln := lowerName(normalizeName(name))
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*ResourceRecord
	for key, recs := range c.records {
		if key.Name != ln {
			continue
		}
		for _, cr := range recs {
			if cr.expires.After(now) {
				result = append(result, cr.rr)
			}
		}
	}
	return result
}

// Remove deletes all records matching the key.
func (c *Cache) Remove(key CacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.records, key)
}

// RemoveName removes all records for a given name.
func (c *Cache) RemoveName(name string) {
	ln := lowerName(normalizeName(name))
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.records {
		if key.Name == ln {
			delete(c.records, key)
		}
	}
}

// Expire purges all expired records from the cache.
func (c *Cache) Expire() int {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for key, recs := range c.records {
		filtered := recs[:0]
		for _, cr := range recs {
			if cr.expires.After(now) {
				filtered = append(filtered, cr)
			} else {
				count++
			}
		}
		if len(filtered) == 0 {
			delete(c.records, key)
		} else {
			c.records[key] = filtered
		}
	}
	return count
}

// HasValidRecord returns true if the cache has a non-expired record for the key.
func (c *Cache) HasValidRecord(key CacheKey) bool {
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cr := range c.records[key] {
		if cr.expires.After(now) {
			return true
		}
	}
	return false
}

// RecordRemainingTTL returns the remaining TTL (in seconds) for the first
// non-expired record matching the key, or 0 if no record exists.
// Used by Browser to determine if a cached record needs refresh (RFC 6762 §5.2).
func (c *Cache) RecordRemainingTTL(key CacheKey) uint32 {
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cr := range c.records[key] {
		if cr.expires.After(now) {
			remaining := time.Until(cr.expires)
			original := time.Duration(cr.rr.TTL) * time.Second
			if original > 0 {
				return uint32(remaining / time.Second)
			}
		}
	}
	return 0
}

// RecordOriginalTTL returns the original TTL of the first non-expired record
// matching the key.
func (c *Cache) RecordOriginalTTL(key CacheKey) uint32 {
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cr := range c.records[key] {
		if cr.expires.After(now) {
			return cr.rr.TTL
		}
	}
	return 0
}

// AllRecords returns all non-expired records in the cache (for debugging).
func (c *Cache) AllRecords() []*ResourceRecord {
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*ResourceRecord
	for _, recs := range c.records {
		for _, cr := range recs {
			if cr.expires.After(now) {
				result = append(result, cr.rr)
			}
		}
	}
	return result
}

// KnownAnswers returns all cached records matching name+type whose remaining
// TTL is more than half of their original TTL.  Used for Known-Answer Suppression
// (RFC 6762 §7.1).
func (c *Cache) KnownAnswers(name string, rrType uint16) []*ResourceRecord {
	key := rrKey(name, rrType)
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*ResourceRecord
	for _, cr := range c.records[key] {
		remaining := time.Until(cr.expires)
		original := time.Duration(cr.rr.TTL) * time.Second
		if remaining > original/2 && cr.expires.After(now) {
			result = append(result, cr.rr)
		}
	}
	return result
}

// recordsEqual compares two resource records for RDATA equality.
func recordsEqual(a, b *ResourceRecord) bool {
	if a.Type != b.Type || lowerName(a.Name) != lowerName(b.Name) {
		return false
	}
	switch a.Type {
	case TypeA, TypeAAAA:
		return a.IP.Equal(b.IP)
	case TypePTR, TypeCNAME, TypeNS:
		return lowerName(a.Target) == lowerName(b.Target)
	case TypeSRV:
		return lowerName(a.Target) == lowerName(b.Target) &&
			a.Port == b.Port && a.Priority == b.Priority && a.Weight == b.Weight
	case TypeTXT:
		if len(a.Text) != len(b.Text) {
			return false
		}
		for i := range a.Text {
			if a.Text[i] != b.Text[i] {
				return false
			}
		}
		return true
	default:
		return string(a.RawData) == string(b.RawData)
	}
}

// sameIP is a helper that safely compares two potentially nil net.IP values.
func sameIP(a, b net.IP) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

// matchDomain checks if a domain name matches a service type prefix.
func matchDomain(name, suffix string) bool {
	return strings.HasSuffix(lowerName(name), lowerName(suffix))
}
