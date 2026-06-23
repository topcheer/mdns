package mdns

import (
	"net"
	"strings"
	"sync"
	"time"
)

// ServiceEvent is sent to Browser subscribers when a service is found or lost.
type ServiceEvent struct {
	Action   int                  // EventAdd or EventRemove
	Instance *ServiceInstanceInfo // the discovered service
}

// EventAdd and EventRemove indicate whether a service appeared or disappeared.
const (
	EventAdd = 1
	EventRemove = 2
)

// Browser discovers service instances of a given type on the network.
// It sends periodic multicast queries and collects responses.
type Browser struct {
	server     *Server
	serviceType string // full service type domain, e.g. "_http._tcp.local."
	domain     string

	mu        sync.RWMutex
	instances map[string]*ServiceInstanceInfo // instance name → info
	listeners []chan ServiceEvent

	ctx    struct{}
	cancel chan struct{}
	wg     sync.WaitGroup
	running bool
}

// Browse creates and starts a browser for the given service type.
// serviceType should be like "_http._tcp" or "_http._tcp.local.".
// The returned channel receives service events (add/remove).
// Call browser.Stop() to stop browsing.
func (s *Server) Browse(serviceType string) (*Browser, error) {
	b := &Browser{
		server:      s,
		serviceType: normalizeServiceTypeDomain(serviceType, s.config.Domain),
		domain:      s.config.Domain,
		instances:   make(map[string]*ServiceInstanceInfo),
		cancel:      make(chan struct{}),
	}

	// Register browser with server.
	s.mu.Lock()
	key := lowerName(b.serviceType)
	s.browsers[key] = b
	s.mu.Unlock()

	return b, nil
}

// normalizeServiceTypeDomain ensures the service type is a full domain.
func normalizeServiceTypeDomain(serviceType, domain string) string {
	// Remove trailing dot for processing.
	t := strings.TrimSuffix(serviceType, ".")
	// If it doesn't end with domain, add it.
	if !strings.HasSuffix(t, strings.TrimSuffix(domain, ".")) {
		t = t + "." + strings.TrimSuffix(domain, ".")
	}
	return t + "."
}

// Start begins the browsing loop.
func (b *Browser) Start() (<-chan ServiceEvent, error) {
	events := make(chan ServiceEvent, 64)

	b.mu.Lock()
	b.listeners = append(b.listeners, events)
	if b.running {
		b.mu.Unlock()
		return events, nil
	}
	b.running = true
	b.mu.Unlock()

	b.wg.Add(1)
	go b.browseLoop()

	return events, nil
}

// browseLoop sends periodic queries for the service type using exponential
// backoff (RFC 6762 §5.2): initial delay 20-120ms, then 1s, 2s, 4s, ... up to 60min.
func (b *Browser) browseLoop() {
	defer b.wg.Done()

	// #4: Initial query after a short random delay (RFC 6762 §5.2).
	initialDelay := time.Duration(20+randIntNRange(100)) * time.Millisecond
	select {
	case <-b.cancel:
		return
	case <-time.After(initialDelay):
	}

	b.sendQuery()

	// #4: Exponential backoff: 1s, 2s, 4s, ... up to 1 hour (RFC 6762 §5.2).
	interval := time.Second
	const maxInterval = time.Hour

	for {
		timer := time.NewTimer(interval)
		select {
		case <-b.cancel:
			timer.Stop()
			return
		case <-timer.C:
			b.sendQuery()
			// Double the interval for next time.
			interval *= 2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
}

// sendQuery sends a multicast query for the service type.
// #5: Includes known answers in the query for Known-Answer Suppression (RFC 6762 §7.1).
// #9: If known answers don't fit in one packet, sets the TC bit and sends multiple packets.
func (b *Browser) sendQuery() {
	q := &Question{
		Name:  b.serviceType,
		Type:  TypePTR,
		Class: ClassIN,
	}

	// #5: Collect known answers (PTR records we already know about).
	// BUG-2 fix: Must set a real TTL (not 0). TTL=0 would be interpreted as
	// a Goodbye packet by the receiver, causing incorrect service removal.
	b.mu.RLock()
	var knownAnswers []*ResourceRecord
	for _, info := range b.instances {
		ptr := &ResourceRecord{
			Name:   b.serviceType,
			Type:   TypePTR,
			Class:  ClassIN,
			TTL:    uint32(DefaultOtherTTL / time.Second), // 75 seconds
			Target: info.Name + "." + b.serviceType,
		}
		knownAnswers = append(knownAnswers, ptr)
	}
	b.mu.RUnlock()

	// Build the query message with known answers.
	msg := &Message{
		Header: Header{
			QDCount: 1,
			ANCount: uint16(len(knownAnswers)),
		},
		Questions: []*Question{q},
		Answers:   knownAnswers,
	}

	// Try to pack the message.
	data, err := msg.Pack()
	if err != nil {
		// #9: If it doesn't fit, set TC bit and send in multiple packets.
		b.server.log("browse: query too large, using TC bit multipacket")
		b.sendQueryMultipacket(q, knownAnswers)
		return
	}

	if err := b.server.conn.WriteMulticast(data); err != nil {
		b.server.log("browse: failed to send query: %v", err)
	}
}

// sendQueryMultipacket implements TC bit multipacket Known-Answer Suppression
// (RFC 6762 §7.2). When known answers don't fit in one packet:
// 1. Send the query with TC=1 in the first packet
// 2. Send continuation packets with additional known answers
// 3. The last packet has TC=0
func (b *Browser) sendQueryMultipacket(q *Question, knownAnswers []*ResourceRecord) {
	// First packet: query + TC=1 + as many answers as fit.
	firstMsg := &Message{
		Header: Header{
			QDCount:          1,
			ANCount:          0, // will be set after packing
			Flags:            flagTruncation, // TC=1
		},
		Questions: []*Question{q},
	}

	// Binary search for max answers that fit in one packet.
	maxFit := 0
	for i := 1; i <= len(knownAnswers); i++ {
		test := &Message{
			Header:    Header{QDCount: 1, ANCount: uint16(i), Flags: flagTruncation},
			Questions: []*Question{q},
			Answers:   knownAnswers[:i],
		}
		if _, err := test.Pack(); err != nil {
			break
		}
		maxFit = i
	}

	if maxFit == 0 {
		// Even query alone is too large; just send the query.
		firstMsg.Answers = nil
	} else {
		firstMsg.Answers = knownAnswers[:maxFit]
		firstMsg.ANCount = uint16(len(firstMsg.Answers))
	}

	data, err := firstMsg.Pack()
	if err == nil {
		b.server.conn.WriteMulticast(data)
	}

	// Send remaining answers in continuation packets (TC=0 on last).
	remaining := knownAnswers[maxFit:]
	const maxPerPacket = 20 // conservative limit
	for i := 0; i < len(remaining); i += maxPerPacket {
		end := i + maxPerPacket
		if end > len(remaining) {
			end = len(remaining)
		}
		isLast := end >= len(remaining)
		flags := uint16(0)
		if !isLast {
			flags = flagTruncation
		}
		contMsg := &Message{
			Header: Header{
				ANCount: uint16(end - i),
				Flags:  flags,
			},
			Answers: remaining[i:end],
		}
		if data, err := contMsg.Pack(); err == nil {
			b.server.conn.WriteMulticast(data)
		}
		// Small delay between continuation packets.
		time.Sleep(400 * time.Millisecond) // RFC 6762 §7.2: 400-500ms gap
	}
}

// refreshExpiringRecords sends targeted queries for records that are
// approaching expiry (RFC 6762 §5.2). Records are refreshed when their
// remaining TTL drops below 20% of the original value.
func (b *Browser) refreshExpiringRecords() {
	b.mu.RLock()
	var toRefresh []string
	for _, info := range b.instances {
		fullName := info.Name + "." + b.serviceType
		srvKey := rrKey(fullName, TypeSRV)
		remaining := b.server.cache.RecordRemainingTTL(srvKey)
		original := b.server.cache.RecordOriginalTTL(srvKey)
		if original > 0 && remaining > 0 {
			// Refresh when remaining TTL drops below 20% of original (80% consumed).
			if remaining <= original/5 {
				toRefresh = append(toRefresh, fullName)
			}
		}
	}
	b.mu.RUnlock()

	// Send targeted SRV queries for expiring records.
	for _, name := range toRefresh {
		q := &Question{
			Name:  name,
			Type:  TypeSRV,
			Class: ClassIN,
		}
		msg := &Message{
			Header:    Header{QDCount: 1},
			Questions: []*Question{q},
		}
		if data, err := msg.Pack(); err == nil {
			b.server.conn.WriteMulticast(data)
		}
	}
}

// randIntNRange returns a random int in [0, n).
func randIntNRange(n int) int {
	if n <= 0 {
		return 0
	}
	return int(time.Now().UnixNano()) % n
}

// Stop stops browsing and unregisters from the server.
func (b *Browser) Stop() {
	b.mu.Lock()
	if !b.running {
		b.mu.Unlock()
		return
	}
	b.running = false
	b.mu.Unlock()

	close(b.cancel)
	b.wg.Wait()

	// Unregister from server.
	b.server.mu.Lock()
	delete(b.server.browsers, lowerName(b.serviceType))
	b.server.mu.Unlock()

	// Close all listener channels.
	b.mu.Lock()
	for _, ch := range b.listeners {
		close(ch)
	}
	b.listeners = nil
	b.mu.Unlock()
}

// onRecordAdd is called by the server when a new/updated record arrives.
func (b *Browser) onRecordAdd(rr *ResourceRecord) {
	// Handle PTR records matching our service type.
	if rr.Type == TypePTR && lowerName(rr.Name) == lowerName(b.serviceType) {
		b.handlePTR(rr)
		return
	}

	// Handle SRV/TXT/A/AAAA records that update known instances.
	if rr.Type == TypeSRV || rr.Type == TypeTXT || rr.Type == TypeA || rr.Type == TypeAAAA {
		b.updateInstancesFromRecord(rr)
	}
}

// handlePTR processes a new PTR record pointing to a service instance.
func (b *Browser) handlePTR(rr *ResourceRecord) {
	instanceName := normalizeName(rr.Target)

	b.mu.RLock()
	if _, exists := b.instances[lowerName(instanceName)]; exists {
		b.mu.RUnlock()
		return // already known
	}
	b.mu.RUnlock()

	// Look up SRV and TXT records in cache to build the full info.
	info := b.resolveInstance(instanceName)
	if info == nil {
		// We got the PTR but might not have SRV/TXT yet. Create partial info.
		info = &ServiceInstanceInfo{
			Name:   extractInstanceName(instanceName, b.serviceType),
			Type:   b.serviceType,
			Domain: b.domain,
		}
	}

	b.mu.Lock()
	b.instances[lowerName(instanceName)] = info
	listeners := b.listeners
	b.mu.Unlock()

	// Notify listeners with a snapshot copy (avoid data race with later updates).
	snapshot := copyServiceInstanceInfo(info)
	for _, ch := range listeners {
		select {
		case ch <- ServiceEvent{Action: EventAdd, Instance: snapshot}:
		default:
		}
	}
}

// updateInstancesFromRecord updates any known instances affected by a
// SRV/TXT/A/AAAA record.
func (b *Browser) updateInstancesFromRecord(rr *ResourceRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()

	updated := false

	for _, info := range b.instances {
		instanceName := info.Name + "." + b.serviceType

		switch rr.Type {
		case TypeSRV:
			if lowerName(rr.Name) == lowerName(instanceName) {
				info.Host = rr.Target
				info.Port = rr.Port
				info.Priority = rr.Priority
				info.Weight = rr.Weight
				updated = true
			}
		case TypeTXT:
			if lowerName(rr.Name) == lowerName(instanceName) {
				info.Text = rr.Text
				updated = true
			}
		case TypeA, TypeAAAA:
			// Check if this IP record matches any instance's host.
			hostName := info.Host
			if hostName != "" && lowerName(rr.Name) == lowerName(normalizeName(hostName)) {
				// Check if IP already present.
				found := false
				for _, ip := range info.IPs {
					if ip.Equal(rr.IP) {
						found = true
						break
					}
				}
				if !found {
					info.IPs = append(info.IPs, rr.IP)
					updated = true
				}
			}
		}
	}

	// If updated, resolve full info from cache to fill in missing fields.
	if updated {
		for instanceKey, info := range b.instances {
			if full := b.resolveInstance(info.Name + "." + b.serviceType); full != nil {
				if full.Host != "" {
					info.Host = full.Host
					info.Port = full.Port
					info.Priority = full.Priority
					info.Weight = full.Weight
				}
				if len(full.Text) > 0 {
					info.Text = full.Text
				}
				if len(full.IPs) > 0 {
					info.IPs = full.IPs
				}
				b.instances[instanceKey] = info
			}
		}
	}
}

// onRecordRemove is called by the server when a record expires or a goodbye arrives.
func (b *Browser) onRecordRemove(rr *ResourceRecord) {
	if rr.Type != TypePTR {
		return
	}
	if lowerName(rr.Name) != lowerName(b.serviceType) {
		return
	}

	instanceName := normalizeName(rr.Target)

	b.mu.Lock()
	info, exists := b.instances[lowerName(instanceName)]
	if !exists {
		b.mu.Unlock()
		return
	}
	delete(b.instances, lowerName(instanceName))
	listeners := b.listeners
	b.mu.Unlock()

	for _, ch := range listeners {
		select {
		case ch <- ServiceEvent{Action: EventRemove, Instance: info}:
		default:
		}
	}
}

// resolveInstance looks up SRV, TXT, A/AAAA records in the cache to build
// a complete ServiceInstanceInfo from an instance name.
func (b *Browser) resolveInstance(instanceName string) *ServiceInstanceInfo {
	srvRecords := b.server.cache.Lookup(rrKey(instanceName, TypeSRV))
	if len(srvRecords) == 0 {
		return nil
	}

	srv := srvRecords[0]
	info := &ServiceInstanceInfo{
		Name:     extractInstanceName(instanceName, b.serviceType),
		Type:     b.serviceType,
		Domain:   b.domain,
		Host:     srv.Target,
		Port:     srv.Port,
		Priority: srv.Priority,
		Weight:   srv.Weight,
	}

	// TXT records.
	txtRecords := b.server.cache.Lookup(rrKey(instanceName, TypeTXT))
	if len(txtRecords) > 0 {
		info.Text = txtRecords[0].Text
	}

	// A/AAAA records for the host.
	aRecords := b.server.cache.Lookup(rrKey(srv.Target, TypeA))
	for _, rr := range aRecords {
		info.IPs = append(info.IPs, rr.IP)
	}
	aaaaRecords := b.server.cache.Lookup(rrKey(srv.Target, TypeAAAA))
	for _, rr := range aaaaRecords {
		info.IPs = append(info.IPs, rr.IP)
	}

	return info
}

// Instances returns all currently known service instances.
func (b *Browser) Instances() []*ServiceInstanceInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var result []*ServiceInstanceInfo
	for _, info := range b.instances {
		result = append(result, info)
	}
	return result
}

// extractInstanceName extracts the human-readable instance name from the full
// domain name. E.g. "My Server._http._tcp.local." → "My Server".
func extractInstanceName(instanceName, serviceType string) string {
	// Remove the service type suffix.
	ln := strings.TrimSuffix(instanceName, ".")
	st := strings.TrimSuffix(serviceType, ".")
	idx := strings.LastIndex(lowerName(ln), lowerName(st))
	if idx > 0 {
		return ln[:idx-1] // -1 for the dot separator
	}
	return ln
}

// copyServiceInstanceInfo creates a deep copy of a ServiceInstanceInfo.
// This is used when sending events so consumers get a stable snapshot
// that won't be mutated by later cache updates.
func copyServiceInstanceInfo(info *ServiceInstanceInfo) *ServiceInstanceInfo {
	if info == nil {
		return nil
	}
	c := &ServiceInstanceInfo{
		Name:     info.Name,
		Type:     info.Type,
		Domain:   info.Domain,
		Host:     info.Host,
		Port:     info.Port,
		Priority: info.Priority,
		Weight:   info.Weight,
	}
	if len(info.IPs) > 0 {
		c.IPs = append([]net.IP(nil), info.IPs...)
	}
	if len(info.Text) > 0 {
		c.Text = append([]string(nil), info.Text...)
	}
	return c
}
