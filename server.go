package mdns

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server is the core mDNS engine. It handles receiving and sending mDNS
// packets, responding to queries, probing for unique names, announcing
// services, and maintaining a record cache.
type Server struct {
	config Config
	conn   *MulticastConn
	cache  *Cache

	mu       sync.RWMutex
	services map[string]*registeredService // instance name -> service
	browsers map[string]*Browser           // service type (lowercase) -> browser
	hostName string
	hostIPs  []net.IP

	// BUG-7: Host A/AAAA records must be probed before serving (RFC 6762 §8.1).
	hostRecords []*ResourceRecord
	hostProbed  atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Rate limiting: track last multicast time per record key (RFC 6762 §6).
	rateMu      sync.Mutex
	rateTracker map[string]time.Time // record key -> last sent time

	// Local subnet info for source address checking (RFC 6762 §11).
	localSubnets []*net.IPNet

	// BUG-9: Passive observation — track queries for names we're interested in.
	passiveMu   sync.Mutex
	passiveSeen map[string]int       // name -> query count
	passiveLast map[string]time.Time // name -> last query time
}

// registeredService tracks a service that has been registered with the server.
type registeredService struct {
	instance *ServiceInstance
	records  []*ResourceRecord
	state    serviceState
	probeCh  chan struct{} // closed when probing is done
}

type serviceState int

const (
	stateIdle serviceState = iota
	stateProbing
	stateAnnounced
	stateConflictLost
	stateConflictRenamed
)

// NewServer creates a new mDNS server with the given configuration.
func NewServer(config Config) (*Server, error) {
	if config.Port == 0 {
		config.Port = DefaultPort
	}
	if config.Domain == "" {
		config.Domain = DefaultDomain
	}
	if config.HostName == "" {
		config.HostName = defaultHostName()
	}
	// Ensure hostname ends with .local. (or configured domain).
	if !strings.HasSuffix(config.HostName, ".") {
		config.HostName += "." + config.Domain
	}

	s := &Server{
		config:      config,
		cache:       NewCache(),
		services:    make(map[string]*registeredService),
		browsers:    make(map[string]*Browser),
		rateTracker: make(map[string]time.Time),
		passiveSeen: make(map[string]int),
		passiveLast: make(map[string]time.Time),
	}

	return s, nil
}

// Start begins listening for mDNS packets and starts all background tasks.
func (s *Server) Start() error {
	conn, err := NewMulticastConn(s.config.Port, s.config.EnableIPv6, s.config.Interfaces)
	if err != nil {
		return fmt.Errorf("mdns: failed to create multicast connection: %w", err)
	}
	s.conn = conn

	// Wire the warning callback so runtime send failures are reported.
	conn.SetWarningFunc(s.warn)

	// Detect local IP addresses.
	// Prefers the default-route interface to avoid advertising VPN/virtual
	// adapter addresses (e.g. Docker, Hyper-V, WSL2, Radmin VPN).
	s.hostIPs = localIPs(s.config.Interfaces)

	// Detect local subnets for source address checking (RFC 6762 §11).
	s.localSubnets = localSubnets()

	// Set up the A/AAAA records for our hostname.
	s.registerHostRecords()

	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Start packet receive loop.
	s.wg.Add(1)
	go s.recvLoop()

	// Start cache expiry loop (also handles passive observation + rate cleanup).
	s.wg.Add(1)
	go s.cacheLoop()

	// BUG-7: Probe host A/AAAA records for uniqueness before serving.
	s.wg.Add(1)
	go s.probeHostRecords()

	s.log("mDNS server started on port %d, hostname %s, %d local IPs",
		s.config.Port, s.config.HostName, len(s.hostIPs))

	// Check multicast route health after startup.
	// If the route is broken (e.g. VPN corrupted the 224.0.0.0/4 route),
	// warn the user so they can take action.
	go s.checkMulticastHealth()

	return nil
}

// Close shuts down the server, sending goodbye packets for all registered services.
func (s *Server) Close() error {
	if s.cancel == nil {
		return nil
	}

	// Send goodbye for all registered services.
	s.mu.RLock()
	for _, rs := range s.services {
		if rs.state == stateAnnounced {
			s.sendGoodbye(rs.records)
		}
	}
	s.mu.RUnlock()

	s.cancel()
	s.conn.Close()
	s.wg.Wait()
	s.log("mDNS server stopped")
	return nil
}

// Cache returns the server's record cache (for debugging/inspection).
func (s *Server) Cache() *Cache { return s.cache }

// Config returns the server configuration.
func (s *Server) Config() Config { return s.config }

// HostName returns the hostname being advertised.
func (s *Server) HostName() string { return s.config.HostName }

// HostIPs returns the local IP addresses being advertised.
func (s *Server) HostIPs() []net.IP { return s.hostIPs }

// --- main loops ---

// recvLoop processes incoming packets.
func (s *Server) recvLoop() {
	defer s.wg.Done()
	pkts := s.conn.Packets()
	for {
		select {
		case <-s.ctx.Done():
			return
		case pkt, ok := <-pkts:
			if !ok {
				return
			}
			s.handlePacket(pkt)
		}
	}
}

// cacheLoop periodically expires stale cache entries and handles passive
// observation of failures (RFC 6762 §10.5).
func (s *Server) cacheLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cache.Expire()
			// BUG-9: Passive observation of failures (RFC 6762 §10.5).
			s.handlePassiveObservation()
			// Cache maintenance queries for browser-tracked records.
			s.handleCacheMaintenance()
			// BUG-11: Clean up rate tracker to prevent memory leak.
			s.cleanupRateTracker()
		}
	}
}

// handlePassiveObservation implements RFC 6762 §10.5.
// When we observe queries from other devices for names we have cached records
// for, but we see no corresponding responses within a reasonable window, we can
// proactively expire those records. This accelerates detection of departed hosts.
func (s *Server) handlePassiveObservation() {
	s.passiveMu.Lock()
	defer s.passiveMu.Unlock()
	now := time.Now()
	for name, lastSeen := range s.passiveLast {
		// If a query was seen more than 3 times in 30 seconds without
		// a corresponding response, the record owner may be gone.
		// Accelerate expiry by reducing TTL.
		queryCount := s.passiveSeen[name]
		if queryCount >= 3 && now.Sub(lastSeen) < 30*time.Second {
			// Check if we have cached records for this name.
			records := s.cache.LookupName(lowerName(name))
			for _, rr := range records {
				// If TTL > 10, reduce it to speed up expiry.
				if rr.TTL > 10 {
					s.log("passive observation: accelerating expiry for %s (seen %d queries without response)", name, queryCount)
					rr.TTL = 10
				}
			}
		}
		// Clean up stale entries.
		if now.Sub(lastSeen) > 60*time.Second {
			delete(s.passiveSeen, name)
			delete(s.passiveLast, name)
		}
	}
}

// trackPassiveQuery records that we've seen a query for a name, used for
// passive observation (RFC 6762 §10.5). Called from handleQuery.
func (s *Server) trackPassiveQuery(name string) {
	s.passiveMu.Lock()
	defer s.passiveMu.Unlock()
	s.passiveSeen[name]++
	s.passiveLast[name] = time.Now()
}

// cleanupRateTracker removes entries older than 5 seconds to prevent
// unbounded memory growth (BUG-11).
func (s *Server) cleanupRateTracker() {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	for key, last := range s.rateTracker {
		if now.Sub(last) > 5*time.Second {
			delete(s.rateTracker, key)
		}
	}
}

// handleCacheMaintenance sends refresh queries for records that are
// actively being browsed and are approaching expiry (RFC 6762 §5.2).
// Records are refreshed at 80%, 85%, 90%, and 95% of their TTL.
func (s *Server) handleCacheMaintenance() {
	s.mu.RLock()
	browsers := make([]*Browser, 0, len(s.browsers))
	for _, b := range s.browsers {
		browsers = append(browsers, b)
	}
	s.mu.RUnlock()

	for _, b := range browsers {
		b.refreshExpiringRecords()
	}
}

// --- packet handling ---

func (s *Server) handlePacket(pkt ReceivedPacket) {
	// Silently drop packets too short to be a valid DNS message (header is 12 bytes).
	// These can come from health-check probes or network noise.
	if len(pkt.Data) < 12 {
		return
	}
	msg, err := UnpackMessage(pkt.Data)
	if err != nil {
		s.log("failed to parse packet from %s: %v", pkt.From, err)
		return
	}

	// mDNS messages must have ID=0 (RFC 6762 §18.12).
	if msg.ID != 0 {
		// This might be a legacy unicast query (from a non-mDNS port).
		if msg.IsQuery() && pkt.From.Port != s.config.Port {
			s.handleLegacyQuery(msg, pkt.From)
		}
		return
	}

	// #14: Validate mDNS compliance — opcode MUST be 0, RCode MUST be 0.
	if !msg.IsValidmDNS() {
		s.log("dropping non-compliant mDNS packet from %s: opcode=%d rcode=%d",
			pkt.From, msg.Opcode(), msg.RCode())
		return
	}

	// #11: Source address check — verify the sender is on a local subnet
	// (RFC 6762 §11). Silently ignore packets from non-local sources.
	if !s.isLocalSubnet(pkt.From.IP) {
		s.log("ignoring mDNS packet from non-local source %s", pkt.From.IP)
		return
	}

	if msg.IsQuery() {
		s.handleQuery(msg, pkt.From)
	} else {
		s.handleResponse(msg, pkt.From)
	}
}

// handleQuery processes an incoming mDNS query (RFC 6762 §6).
func (s *Server) handleQuery(msg *Message, from *net.UDPAddr) {
	// Ignore our own queries (multicast loopback).
	ownQuery := false
	for _, hostIP := range s.hostIPs {
		if hostIP.Equal(from.IP) {
			ownQuery = true
			break
		}
	}

	// Check for probe queries (authority section has records) — RFC 6762 §8.2.
	for _, ns := range msg.Authorities {
		s.handleProbe(ns, from)
	}

	// BUG-9: Track queries from other devices for passive observation.
	if !ownQuery {
		for _, q := range msg.Questions {
			s.trackPassiveQuery(q.Name)
		}
	}

	// Build response records.
	var answerRecords []*ResourceRecord
	var additionalRecords []*ResourceRecord
	hasUnique := false // tracks if any answer records are unique (cache-flush)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, q := range msg.Questions {
		ln := lowerName(normalizeName(q.Name))
		qType := q.Type
		qClass := q.Class & ^cacheFlushBit

		// #12: Reverse address mapping (RFC 6762 §4 + §6762).
		// Handle queries for X.X.X.X.in-addr.arpa. or x.x.x.x.ip6.arpa.
		if reversePTR := s.handleReverseMapping(q); reversePTR != nil {
			if !inKnownAnswers(reversePTR, msg.Answers) {
				answerRecords = append(answerRecords, reversePTR)
			}
			continue
		}

		// Check registered services.
		for _, rs := range s.services {
			if rs.state != stateAnnounced {
				continue
			}
			for _, rr := range rs.records {
				if matchesQuestion(rr, q) && !inKnownAnswers(rr, msg.Answers) {
					answerRecords = append(answerRecords, rr)
					if rr.CacheFlush {
						hasUnique = true
					}
				}
			}

			// For PTR queries matching a service type, include SRV/TXT/A/AAAA
			// records in the additional section (RFC 6762 §6.2).
			if qType == TypePTR || qType == TypeAny {
				svcType := rs.instance.ServiceType()
				if lowerName(svcType) == ln {
					for _, rr := range rs.records {
						if rr.Type == TypeSRV || rr.Type == TypeTXT || rr.Type == TypeA || rr.Type == TypeAAAA {
							if !containsRR(answerRecords, rr) && !containsRR(additionalRecords, rr) {
								additionalRecords = append(additionalRecords, rr)
							}
						}
					}
				}
			}

			// #3: NSEC negative responses (RFC 6762 §6.1).
			// If a query is for a name we own but a type we don't have,
			// generate an NSEC record listing the types we DO have.
			instanceName := lowerName(normalizeName(rs.instance.InstanceName()))
			if ln == instanceName && qType != TypeAny && qType != TypePTR {
				hasType := false
				for _, rr := range rs.records {
					if rr.Type == qType && lowerName(normalizeName(rr.Name)) == ln {
						hasType = true
						break
					}
				}
				if !hasType {
					nsec := s.generateNSEC(q.Name, rs.records)
					if nsec != nil && !inKnownAnswers(nsec, msg.Answers) {
						answerRecords = append(answerRecords, nsec)
						hasUnique = true // NSEC records are unique
					}
				}
			}
		}

		// Check host records (A/AAAA) — only after probing is complete.
		if s.hostProbed.Load() {
			for _, rr := range s.cache.LookupName(ln) {
				if matchesQuestion(rr, q) && !inKnownAnswers(rr, msg.Answers) && !containsRR(answerRecords, rr) {
					answerRecords = append(answerRecords, rr)
					if rr.CacheFlush {
						hasUnique = true
					}
				}
			}
		}

		// Handle _services._dns-sd._udp.local. enumeration (RFC 6763).
		if ln == "_services._dns-sd._udp."+lowerName(s.config.Domain) {
			for _, rs := range s.services {
				if rs.state != stateAnnounced {
					continue
				}
				ptr := &ResourceRecord{
					Name:       q.Name,
					Type:       TypePTR,
					Class:      ClassIN,
					TTL:        uint32(DefaultOtherTTL / time.Second),
					CacheFlush: false,
					Target:     rs.instance.InstanceName(),
				}
				if !inKnownAnswers(ptr, msg.Answers) && !containsRR(answerRecords, ptr) {
					answerRecords = append(answerRecords, ptr)
				}
			}
		}

		_ = qClass
	}

	responseRecords := answerRecords

	if len(responseRecords) == 0 && len(additionalRecords) == 0 {
		return
	}

	// Determine if this is a unicast-response query (QU bit set).
	unicastResponse := false
	for _, q := range msg.Questions {
		if q.Class&cacheFlushBit != 0 {
			unicastResponse = true
			break
		}
	}

	if unicastResponse {
		// Send unicast response immediately (RFC 6762 §5.4).
		go s.sendResponseWithAdditional(responseRecords, additionalRecords, from, false)
	} else if hasUnique {
		// #7: For unique records, respond within 10ms (RFC 6762 §6).
		// Unique records need quick authoritative answers.
		go func() {
			select {
			case <-s.ctx.Done():
			case <-time.After(10 * time.Millisecond):
				s.sendResponseWithAdditional(responseRecords, additionalRecords, nil, false)
			}
		}()
	} else {
		// Delay multicast response randomly 20-120ms (RFC 6762 §6).
		go func() {
			delay := time.Duration(rand.IntN(100)+20) * time.Millisecond
			select {
			case <-s.ctx.Done():
			case <-time.After(delay):
				s.sendResponseWithAdditional(responseRecords, additionalRecords, nil, false)
			}
		}()
	}
}

// handleResponse processes an incoming mDNS response (RFC 6762 §7, §10).
func (s *Server) handleResponse(msg *Message, from *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Process all records: answers + additionals (both get cached).
	var allRecords []*ResourceRecord
	allRecords = append(allRecords, msg.Answers...)
	allRecords = append(allRecords, msg.Additionals...)

	// First pass: update cache (so all related records are available
	// before browsers try to resolve instances).
	for _, rr := range allRecords {
		if rr.TTL == 0 {
			s.cache.Remove(rrKey(rr.Name, rr.Type))
			s.log("goodbye: %s", rr)
			continue
		}
		s.detectConflictLocked(rr, from)
		s.cache.Upsert(rr, from.IP)
		// BUG-9: Clear passive observation tracking — we got a response.
		s.passiveMu.Lock()
		delete(s.passiveSeen, rr.Name)
		delete(s.passiveLast, rr.Name)
		s.passiveMu.Unlock()
	}

	// Second pass: notify browsers (cache now has all records from this message).
	for _, rr := range allRecords {
		if rr.TTL == 0 {
			s.notifyRemoval(rr)
		} else {
			s.notifyAddition(rr)
		}
	}
}

// handleLegacyQuery handles a legacy unicast DNS query (from a non-mDNS port).
// Per RFC 6762 §6.7, we respond via unicast without delay.
func (s *Server) handleLegacyQuery(msg *Message, from *net.UDPAddr) {
	var responseRecords []*ResourceRecord

	s.mu.RLock()
	for _, q := range msg.Questions {
		for _, rs := range s.services {
			if rs.state != stateAnnounced {
				continue
			}
			for _, rr := range rs.records {
				if matchesQuestion(rr, q) {
					responseRecords = append(responseRecords, rr)
				}
			}
		}
	}
	s.mu.RUnlock()

	if len(responseRecords) > 0 {
		// Build a response with the original ID.
		resp := &Message{
			Header: Header{
				ID:      msg.ID,
				Flags:   flagResponse | flagAuthoritative,
				ANCount: uint16(len(responseRecords)),
			},
			Answers: responseRecords,
		}
		data, err := resp.Pack()
		if err != nil {
			s.log("failed to pack legacy response: %v", err)
			return
		}
		if s.conn == nil {
			return
		}
		if _, err := s.conn.WriteTo(data, from); err != nil {
			s.log("failed to send legacy response: %v", err)
		}
	}
}

// handleProbe checks an authority record from a probe query for conflicts
// with our registered records and implements tiebreaking (RFC 6762 §8.2).
//
// Tiebreaking: when two devices probe the same unique name simultaneously,
// the one with lexicographically later rdata wins. The loser must rename.
//
// Note: We do NOT filter by source IP. Multiple mDNS instances on the same
// machine share the same IPs (multicast loopback), so IP filtering would
// break same-machine multi-instance support. Instead, we check whether ANY
// of our records match the probe record — if so, it's self-loopback.
func (s *Server) handleProbe(ns *ResourceRecord, from *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rs := range s.services {
		if rs.state != stateAnnounced && rs.state != stateProbing {
			continue
		}

		// Collect all our records that share name+type with the probe record.
		// Also check if any of them have identical RDATA (self-loopback).
		hasMatch := false
		var conflictingRR *ResourceRecord
		for _, ourRR := range rs.records {
			if !ourRR.CacheFlush {
				continue
			}
			if lowerName(ourRR.Name) != lowerName(ns.Name) {
				continue
			}
			if ourRR.Type != ns.Type {
				continue
			}
			if recordsEqual(ourRR, ns) {
				// Found an exact match — this is our own probe loopback'd.
				hasMatch = true
				break
			}
			conflictingRR = ourRR
		}

		// If any of our records exactly match the probe record, skip —
		// this is our own multicast loopback (we have multiple A records
		// and each gets compared against all others).
		if hasMatch {
			continue
		}

		if conflictingRR == nil {
			continue
		}

		if rs.state == stateAnnounced {
			// We're already announced — defend our record by sending it.
			s.log("defending record %s against probe from %s", conflictingRR, from.IP)
			go s.sendResponseMulticast([]*ResourceRecord{conflictingRR})
		} else if rs.state == stateProbing {
			// #2: Tiebreaking during simultaneous probe.
			if probeLoses(conflictingRR, ns) {
				s.log("tiebreak: we lose on %s (our rdata < their rdata)", conflictingRR.Name)
				rs.state = stateConflictLost
				close(rs.probeCh)
			}
		}
	}
}

// detectConflictLocked checks if a received record conflicts with our
// announced services. Must be called with s.mu held.
// Note: We do NOT filter by source IP — see handleProbe comment.
// We first check if any of our records exactly match (self-loopback);
// only if none match do we check for conflict.
func (s *Server) detectConflictLocked(rr *ResourceRecord, from *net.UDPAddr) {
	_ = from

	for _, rs := range s.services {
		if rs.state != stateAnnounced {
			continue
		}
		// First pass: check if ANY record matches exactly (self-loopback).
		hasMatch := false
		for _, ourRR := range rs.records {
			if !ourRR.CacheFlush {
				continue
			}
			if recordsEqual(ourRR, rr) {
				hasMatch = true
				break
			}
		}
		if hasMatch {
			continue
		}
		// Second pass: check for conflict (same name+type, different rdata).
		for _, ourRR := range rs.records {
			if !ourRR.CacheFlush {
				continue
			}
			if recordsConflict(ourRR, rr) {
				s.log("conflict: received %s conflicts with our record", rr)
			}
		}
	}
}

// --- response sending ---

func (s *Server) sendResponseMulticast(records []*ResourceRecord) {
	s.sendResponseWithAdditional(records, nil, nil, false)
}

// sendResponseWithAdditional sends a response with answer and additional records.
// If to is nil, sends via multicast; otherwise sends via unicast.
// Rate limiting (RFC 6762 §6) is applied internally to all multicast responses.
// The rateLimit parameter is retained for API compatibility but rate limiting
// now always applies to multicast.
func (s *Server) sendResponseWithAdditional(answers, additionals []*ResourceRecord, to *net.UDPAddr, _ bool) {
	// Deduplicate answers.
	var dedupAnswers []*ResourceRecord
	for _, rr := range answers {
		if !containsRR(dedupAnswers, rr) {
			dedupAnswers = append(dedupAnswers, rr)
		}
	}
	// Deduplicate additionals (and exclude any already in answers).
	var dedupAdditionals []*ResourceRecord
	for _, rr := range additionals {
		if !containsRR(dedupAnswers, rr) && !containsRR(dedupAdditionals, rr) {
			dedupAdditionals = append(dedupAdditionals, rr)
		}
	}

	// #8: Apply multicast rate limiting to ALL multicast responses.
	// Per RFC 6762 §6: a responder MUST NOT multicast a record more than
	// once per second (except for probe responses at 250ms intervals).
	// For query responses, we track the rate per record. If a record was
	// sent within the last second, we skip it. This prevents flooding.
	if to == nil {
		var filtered []*ResourceRecord
		for _, rr := range dedupAnswers {
			if s.canSendMulticast(rr) {
				filtered = append(filtered, rr)
			}
		}
		if len(filtered) == 0 && len(dedupAnswers) > 0 {
			// All records were rate-limited.
			return
		}
		if len(filtered) > 0 {
			dedupAnswers = filtered
		}
	}

	resp := &Message{
		Header: Header{
			Flags:   flagResponse | flagAuthoritative,
			ANCount: uint16(len(dedupAnswers)),
			ARCount: uint16(len(dedupAdditionals)),
		},
		Answers:     dedupAnswers,
		Additionals: dedupAdditionals,
	}
	data, err := resp.Pack()
	if err != nil {
		s.log("failed to pack response: %v", err)
		return
	}
	if s.conn == nil {
		return
	}
	if to == nil {
		if err := s.conn.WriteMulticast(data); err != nil {
			s.log("failed to send multicast response: %v", err)
		}
	} else {
		if _, err := s.conn.WriteTo(data, to); err != nil {
			s.log("failed to send unicast response: %v", err)
		}
	}
}

func (s *Server) sendResponseUnicast(records []*ResourceRecord, to *net.UDPAddr) {
	resp := &Message{
		Header: Header{
			Flags:   flagResponse | flagAuthoritative,
			ANCount: uint16(len(records)),
		},
		Answers: records,
	}
	data, err := resp.Pack()
	if err != nil {
		s.log("failed to pack unicast response: %v", err)
		return
	}
	if s.conn == nil {
		return
	}
	if _, err := s.conn.WriteTo(data, to); err != nil {
		s.log("failed to send unicast response: %v", err)
	}
}

func (s *Server) sendGoodbye(records []*ResourceRecord) {
	var goodbyes []*ResourceRecord
	for _, rr := range records {
		gb := *rr // copy
		gb.TTL = 0
		goodbyes = append(goodbyes, &gb)
	}
	resp := &Message{
		Header: Header{
			Flags:   flagResponse | flagAuthoritative,
			ANCount: uint16(len(goodbyes)),
		},
		Answers: goodbyes,
	}
	data, err := resp.Pack()
	if err != nil {
		s.log("failed to pack goodbye: %v", err)
		return
	}
	if s.conn == nil {
		return
	}
	if err := s.conn.WriteMulticast(data); err != nil {
		s.log("failed to send goodbye: %v", err)
	}
}

// --- host records ---

func (s *Server) registerHostRecords() {
	hostName := normalizeName(s.config.HostName)
	// IPv4 addresses come first for advertisement priority.
	sortedIPs := sortIPsIPv4First(s.hostIPs)
	for _, ip := range sortedIPs {
		var rr *ResourceRecord
		if ip4 := ip.To4(); ip4 != nil {
			rr = &ResourceRecord{
				Name:       hostName,
				Type:       TypeA,
				Class:      ClassIN,
				TTL:        uint32(DefaultHostTTL / time.Second),
				CacheFlush: true,
				IP:         ip4,
			}
		} else {
			rr = &ResourceRecord{
				Name:       hostName,
				Type:       TypeAAAA,
				Class:      ClassIN,
				TTL:        uint32(DefaultHostTTL / time.Second),
				CacheFlush: true,
				IP:         ip,
			}
		}
		// BUG-7: Store records for probing; don't cache yet.
		// Records will be cached after successful probing (RFC 6762 §8.1).
		s.hostRecords = append(s.hostRecords, rr)
	}
}

// probeHostRecords probes the hostname A/AAAA records for uniqueness
// before serving them (RFC 6762 §8.1). After successful probing,
// records are cached and announced.
func (s *Server) probeHostRecords() {
	defer s.wg.Done()
	if len(s.hostRecords) == 0 {
		return
	}

	// Random initial delay [0, 250ms].
	delay := time.Duration(rand.IntN(250)) * time.Millisecond
	select {
	case <-s.ctx.Done():
		return
	case <-time.After(delay):
	}

	// Build probe message for host records.
	probeMsg := s.buildProbeMessage(s.hostRecords)

	// Send 3 probes, 250ms apart.
	for i := 0; i < int(DefaultProbeCount); i++ {
		data, err := probeMsg.Pack()
		if err != nil {
			return
		}
		if s.conn == nil {
			return
		}
		if err := s.conn.WriteMulticast(data); err != nil {
			return
		}
		if i < int(DefaultProbeCount)-1 {
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(DefaultProbeWait):
			}
		}
	}

	// Wait one more probe interval.
	select {
	case <-s.ctx.Done():
		return
	case <-time.After(DefaultProbeWait):
	}

	// No conflict — cache the records and announce.
	for _, rr := range s.hostRecords {
		s.cache.Upsert(rr, nil)
	}
	s.hostProbed.Store(true)
	s.log("host records probed and announced: %s", normalizeName(s.config.HostName))

	// Send announcement.
	s.sendResponseMulticast(s.hostRecords)
}

// --- browser notifications ---

func (s *Server) notifyAddition(rr *ResourceRecord) {
	for _, b := range s.browsers {
		b.onRecordAdd(rr)
	}
}

func (s *Server) notifyRemoval(rr *ResourceRecord) {
	for _, b := range s.browsers {
		b.onRecordRemove(rr)
	}
}

// --- helpers ---

func (s *Server) log(format string, args ...any) {
	if s.config.LogFunc != nil {
		s.config.LogFunc(format, args...)
	}
}

// warn delivers a warning to the configured WarningFunc, or falls back
// to logging if WarningFunc is not set.
func (s *Server) warn(w Warning) {
	if s.config.WarningFunc != nil {
		s.config.WarningFunc(w)
		return
	}
	// Fall back to debug log.
	s.log("WARNING [%s] %s — %s", w.Code, w.Message, w.Hint)
}

// checkMulticastHealth verifies that the system can send multicast packets.
// Called asynchronously during Server.Start() to avoid blocking startup.
func (s *Server) checkMulticastHealth() {
	if err := CheckMulticastRoute(); err != nil {
		s.warn(Warning{
			Code:    "multicast_route_broken",
			Message: "system cannot send multicast packets — mDNS discovery and advertising will not work",
			Hint:    "check 'netstat -rn | grep 224' for a rejected (RTF_REJECT) or missing route; disconnect VPN clients (sing-box, Tailscale, Clash) or reboot",
		})
	}
}

// matchesQuestion checks if a resource record answers a question.
func matchesQuestion(rr *ResourceRecord, q *Question) bool {
	qType := q.Type
	qClass := q.Class & ^cacheFlushBit
	rrClass := rr.Class

	if qType == TypeAny {
		return lowerName(rr.Name) == lowerName(normalizeName(q.Name))
	}
	return rr.Type == qType &&
		lowerName(rr.Name) == lowerName(normalizeName(q.Name)) &&
		(qClass == ClassAny || rrClass == ClassAny || rrClass == qClass)
}

// inKnownAnswers checks if rr is already in the known-answer section of a query,
// AND the known answer has a TTL that is at least half of what we would send.
// Per RFC 6762 §7.1: suppress response only if the querier already has a
// current copy of the record with a TTL at least half of the correct value.
func inKnownAnswers(rr *ResourceRecord, known []*ResourceRecord) bool {
	for _, ka := range known {
		if recordsEqual(rr, ka) {
			// Only suppress if the known answer's TTL is >= 50% of our record's TTL.
			if ka.TTL >= rr.TTL/2 {
				return true
			}
		}
	}
	return false
}

// containsRR checks if records already contains a record equal to rr.
func containsRR(records []*ResourceRecord, rr *ResourceRecord) bool {
	for _, r := range records {
		if recordsEqual(r, rr) {
			return true
		}
	}
	return false
}

// recordsConflict checks if two records have the same name+type but different RDATA.
func recordsConflict(a, b *ResourceRecord) bool {
	if a.Type != b.Type || lowerName(a.Name) != lowerName(b.Name) {
		return false
	}
	return !recordsEqual(a, b)
}

// localIPs returns the local IP addresses for advertising.
//
// If interfaces is non-empty, only addresses on those interfaces are returned.
// Otherwise, the default-route interface is auto-detected and its IP is
// returned first, followed by addresses from other physical interfaces.
// This avoids advertising VPN/virtual adapter addresses (Docker, Hyper-V,
// WSL2, Radmin VPN, etc.) that are unreachable on the LAN.
func localIPs(interfaces []string) []net.IP {
	// If explicit interfaces are configured, return only their addresses.
	if len(interfaces) > 0 {
		return ipsForInterfaces(interfaces)
	}

	// Auto-detect: prefer the default-route interface.
	if defaultIP := defaultRouteIPv4(); defaultIP != nil {
		ips := []net.IP{defaultIP}
		// Also include IPv6 addresses from the same interface for AAAA records.
		return ips
	}

	// Fallback: all non-loopback addresses from active interfaces.
	return ipsForInterfaces(nil)
}

// ipsForInterfaces returns all non-loopback addresses from the given interfaces.
// If interfaces is empty/nil, all active interfaces are considered.
func ipsForInterfaces(interfaces []string) []net.IP {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	nameSet := make(map[string]bool, len(interfaces))
	for _, n := range interfaces {
		nameSet[n] = true
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(nameSet) > 0 && !nameSet[iface.Name] {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips
}

// defaultHostName generates a default hostname from the system hostname.
func defaultHostName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "mdns-host"
	}
	// Sanitize: replace non-alphanumeric with hyphens.
	var sb strings.Builder
	for _, r := range host {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			sb.WriteRune(r)
		} else if r == '.' || r == ' ' {
			sb.WriteRune('-')
		}
	}
	result := sb.String()
	if result == "" {
		return "mdns-host"
	}
	return result
}

// --- #2: Probe tiebreaking (RFC 6762 §8.2) ---

// probeLoses returns true if our rdata is lexicographically earlier than
// their rdata, meaning we lose the tiebreak and must rename.
// Per RFC 6762 §8.2: "The winner is the record whose rdata is lexicographically
// later, treating rdata as a raw block of bytes (after canonical ordering)."
func probeLoses(ours, theirs *ResourceRecord) bool {
	oursRDATA := canonicalRDATA(ours)
	theirsRDATA := canonicalRDATA(theirs)
	return string(oursRDATA) < string(theirsRDATA)
}

// canonicalRDATA returns the RDATA of a record in canonical wire format
// for lexicographic comparison.
func canonicalRDATA(rr *ResourceRecord) []byte {
	var buf []byte
	comp := make(map[string]int)
	// Temporarily write just the RDATA portion.
	rrCopy := *rr
	rrCopy.Name = lowerName(normalizeName(rr.Name))
	tempBuf := &buf
	// Write the RDATA using the pack method but skip the header.
	// We only need the RDATA portion for comparison.
	switch rr.Type {
	case TypeA, TypeAAAA:
		if rr.IP != nil {
			if ip4 := rr.IP.To4(); ip4 != nil && rr.Type == TypeA {
				*tempBuf = append(*tempBuf, ip4...)
			} else if ip6 := rr.IP.To16(); ip6 != nil && rr.Type == TypeAAAA {
				*tempBuf = append(*tempBuf, ip6...)
			}
		}
	case TypeSRV:
		*tempBuf = append(*tempBuf, byte(rr.Priority>>8), byte(rr.Priority))
		*tempBuf = append(*tempBuf, byte(rr.Weight>>8), byte(rr.Weight))
		*tempBuf = append(*tempBuf, byte(rr.Port>>8), byte(rr.Port))
		_ = writeName(tempBuf, lowerName(normalizeName(rr.Target)), comp)
	case TypePTR, TypeCNAME, TypeNS:
		_ = writeName(tempBuf, lowerName(normalizeName(rr.Target)), comp)
	case TypeTXT:
		for _, s := range rr.Text {
			*tempBuf = append(*tempBuf, byte(len(s)))
			*tempBuf = append(*tempBuf, s...)
		}
	default:
		*tempBuf = append(*tempBuf, rr.RawData...)
	}
	return buf
}

// --- #8: Multicast rate limiting (RFC 6762 §6) ---

// canSendMulticast checks if a record can be multicast without exceeding the
// rate limit (at most once per second per record, RFC 6762 §6).
// Probes may be sent at 250ms intervals.
func (s *Server) canSendMulticast(rr *ResourceRecord) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	key := lowerName(normalizeName(rr.Name)) + ":" + fmt.Sprintf("%d", rr.Type) + ":" + rdataKey(rr)
	if last, ok := s.rateTracker[key]; ok {
		if time.Since(last) < time.Second {
			return false
		}
	}
	s.rateTracker[key] = time.Now()
	return true
}

// rdataKey generates a compact string key from RR data for rate tracking.
func rdataKey(rr *ResourceRecord) string {
	switch rr.Type {
	case TypeA, TypeAAAA:
		if rr.IP != nil {
			return rr.IP.String()
		}
	case TypePTR, TypeCNAME, TypeNS:
		return lowerName(normalizeName(rr.Target))
	case TypeSRV:
		return fmt.Sprintf("%s:%d", lowerName(normalizeName(rr.Target)), rr.Port)
	case TypeTXT:
		return strings.Join(rr.Text, ",")
	}
	return fmt.Sprintf("%x", rr.RawData)
}

// --- #3: NSEC negative responses (RFC 6762 §6.1) ---

// generateNSEC creates an NSEC record for a name listing the types of records
// that DO exist, to indicate the absence of other types.
func (s *Server) generateNSEC(name string, records []*ResourceRecord) *ResourceRecord {
	seen := make(map[uint16]bool)
	for _, rr := range records {
		if lowerName(normalizeName(rr.Name)) == lowerName(normalizeName(name)) {
			seen[rr.Type] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	var types []uint16
	for t := range seen {
		types = append(types, t)
	}
	return &ResourceRecord{
		Name:        name,
		Type:        TypeNSEC,
		Class:       ClassIN,
		TTL:         uint32(DefaultOtherTTL / time.Second),
		CacheFlush:  true,
		NextDomain:  name,
		TypeBitMaps: types,
	}
}

// --- #12: Reverse address mapping (RFC 6762 §4) ---

// handleReverseMapping checks if a query is for a reverse DNS name
// (e.g. 100.1.168.192.in-addr.arpa.) and returns a PTR record if we
// own the corresponding IP address.
func (s *Server) handleReverseMapping(q *Question) *ResourceRecord {
	ln := lowerName(normalizeName(q.Name))
	if !strings.HasSuffix(ln, ".in-addr.arpa.") && !strings.HasSuffix(ln, ".ip6.arpa.") {
		return nil
	}
	if q.Type != TypePTR && q.Type != TypeAny {
		return nil
	}

	// Parse the IP from the reverse name.
	ip := reverseNameToIP(q.Name)
	if ip == nil {
		return nil
	}

	// Check if we own this IP.
	for _, hostIP := range s.hostIPs {
		if hostIP.Equal(ip) {
			return &ResourceRecord{
				Name:       q.Name,
				Type:       TypePTR,
				Class:      ClassIN,
				TTL:        uint32(DefaultHostTTL / time.Second),
				CacheFlush: true,
				Target:     normalizeName(s.config.HostName),
			}
		}
	}

	// Also check service IPs (caller must already hold s.mu.RLock).
	for _, rs := range s.services {
		if rs.state != stateAnnounced {
			continue
		}
		for _, rr := range rs.records {
			if (rr.Type == TypeA || rr.Type == TypeAAAA) && rr.IP != nil && rr.IP.Equal(ip) {
				return &ResourceRecord{
					Name:       q.Name,
					Type:       TypePTR,
					Class:      ClassIN,
					TTL:        uint32(DefaultHostTTL / time.Second),
					CacheFlush: true,
					Target:     normalizeName(rr.Name),
				}
			}
		}
	}
	return nil
}

// reverseNameToIP converts a reverse DNS name back to an IP address.
// Supports both IPv4 (.in-addr.arpa.) and IPv6 (.ip6.arpa.) formats.
func reverseNameToIP(name string) net.IP {
	ln := strings.TrimSuffix(lowerName(name), ".")

	if strings.HasSuffix(ln, ".in-addr.arpa") {
		// IPv4: A.B.C.D.in-addr.arpa → D.C.B.A
		prefix := strings.TrimSuffix(ln, ".in-addr.arpa")
		parts := strings.Split(prefix, ".")
		if len(parts) != 4 {
			return nil
		}
		var octets [4]byte
		for i := 0; i < 4; i++ {
			var b int
			if _, err := fmt.Sscanf(parts[3-i], "%d", &b); err != nil || b < 0 || b > 255 {
				return nil
			}
			octets[i] = byte(b)
		}
		return net.IPv4(octets[0], octets[1], octets[2], octets[3])
	}

	if strings.HasSuffix(ln, ".ip6.arpa") {
		// IPv6: x.x.x.x.x.x.x.x....ip6.arpa (32 nibbles, least significant first)
		// Each nibble is a single hex digit.
		prefix := strings.TrimSuffix(ln, ".ip6.arpa")
		parts := strings.Split(prefix, ".")
		if len(parts) != 32 {
			return nil
		}
		var ip [16]byte
		// Parts are in reverse nibble order: parts[0] is the last nibble.
		// We need to reconstruct the 16-byte IPv6 address.
		for i := 0; i < 16; i++ {
			// High nibble is parts[31 - i*2], low nibble is parts[30 - i*2].
			hiIdx := 31 - i*2
			loIdx := 30 - i*2
			hi, err1 := hexNibble(parts[hiIdx])
			lo, err2 := hexNibble(parts[loIdx])
			if err1 != nil || err2 != nil {
				return nil
			}
			ip[i] = byte(hi<<4 | lo)
		}
		return net.IP(ip[:])
	}

	return nil
}

// hexNibble converts a single hex character to its 4-bit value.
func hexNibble(s string) (int, error) {
	if len(s) != 1 {
		return 0, fmt.Errorf("expected single hex digit, got %q", s)
	}
	c := s[0]
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), nil
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, nil
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit %q", c)
	}
}

// --- #11: Source address check (RFC 6762 §11) ---

// isLocalSubnet checks if an IP address is on one of our local subnets.
// Per RFC 6762 §11, mDNS receivers MUST silently ignore mDNS responses
// whose source address is not in a local subnet.
func (s *Server) isLocalSubnet(ip net.IP) bool {
	// Always allow loopback (for testing and local development).
	if ip.IsLoopback() {
		return true
	}
	// Allow link-local addresses (mDNS spec operates on link-local scope).
	if ip.IsLinkLocalUnicast() {
		return true
	}
	// Check against configured local subnets.
	for _, subnet := range s.localSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	// No match — reject non-local source.
	return false
}

// localSubnets returns all local network subnets.
func localSubnets() []*net.IPNet {
	var subnets []*net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		return subnets
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				subnets = append(subnets, v)
			}
		}
	}
	return subnets
}
