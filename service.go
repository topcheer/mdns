package mdns

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// RegisterService registers a service instance with the mDNS server.
// The service will be probed for uniqueness, then announced on the network.
// Returns an error if a service with the same instance name is already registered.
func (s *Server) RegisterService(svc *ServiceInstance) error {
	if svc.Name == "" || svc.Type == "" {
		return fmt.Errorf("mdns: service name and type are required")
	}

	// Set defaults.
	if svc.Domain == "" {
		svc.Domain = s.config.Domain
	}
	if svc.Host == "" {
		svc.Host = s.config.HostName
	}
	if len(svc.IPs) == 0 {
		svc.IPs = s.hostIPs
	}

	instanceName := lowerName(normalizeName(svc.InstanceName()))

	s.mu.Lock()
	if _, exists := s.services[instanceName]; exists {
		s.mu.Unlock()
		return fmt.Errorf("mdns: service %q is already registered", svc.InstanceName())
	}

	rs := &registeredService{
		instance: svc,
		records:  s.generateServiceRecords(svc),
		state:    stateIdle,
		probeCh:  make(chan struct{}),
	}
	s.services[instanceName] = rs
	s.mu.Unlock()

	s.log("registering service: %s (%d records)", svc.InstanceName(), len(rs.records))

	// Start probing.
	go s.probeService(rs)

	return nil
}

// UnregisterService removes a previously registered service and sends goodbye.
func (s *Server) UnregisterService(svc *ServiceInstance) error {
	instanceName := lowerName(normalizeName(svc.InstanceName()))

	s.mu.Lock()
	rs, exists := s.services[instanceName]
	if !exists {
		s.mu.Unlock()
		return fmt.Errorf("mdns: service %q is not registered", svc.InstanceName())
	}
	delete(s.services, instanceName)
	s.mu.Unlock()

	// Send goodbye if the service was announced.
	if rs.state == stateAnnounced {
		s.sendGoodbye(rs.records)
	}

	s.log("unregistered service: %s", svc.InstanceName())
	return nil
}

// generateServiceRecords creates all DNS records needed for a service instance:
//   - PTR: _service._proto.domain → instance._service._proto.domain
//   - SRV: instance._service._proto.domain → host:port
//   - TXT: instance._service._proto.domain → text data
//   - A/AAAA: host → IP addresses
func (s *Server) generateServiceRecords(svc *ServiceInstance) []*ResourceRecord {
	var records []*ResourceRecord

	svcType := svc.ServiceType()
	instanceName := svc.InstanceName()
	hostName := normalizeName(svc.Host)
	hostTTL := uint32(DefaultHostTTL / time.Second)
	otherTTL := uint32(DefaultOtherTTL / time.Second)
	if svc.TTL > 0 {
		hostTTL = svc.TTL
		otherTTL = svc.TTL
	}

	// PTR record: service type → instance.
	records = append(records, &ResourceRecord{
		Name:  svcType,
		Type:  TypePTR,
		Class: ClassIN,
		TTL:   otherTTL,
		Target: instanceName,
	})

	// SRV record: instance → host:port.
	records = append(records, &ResourceRecord{
		Name:       instanceName,
		Type:       TypeSRV,
		Class:      ClassIN,
		TTL:        hostTTL,
		CacheFlush: true,
		Priority:   svc.Priority,
		Weight:     svc.Weight,
		Port:       svc.Port,
		Target:     hostName,
	})

	// TXT record: instance → text.
	text := svc.Text
	if text == nil {
		text = []string{}
	}
	records = append(records, &ResourceRecord{
		Name:       instanceName,
		Type:       TypeTXT,
		Class:      ClassIN,
		TTL:        otherTTL,
		CacheFlush: true,
		Text:       text,
	})

	// A/AAAA records for the host.
	// IPv4 addresses are placed BEFORE IPv6 in the record list, ensuring
	// that service advertisement prefers IPv4 for connectivity.
	sortedIPs := sortIPsIPv4First(svc.IPs)
	for _, ip := range sortedIPs {
		if ip4 := ip.To4(); ip4 != nil {
			records = append(records, &ResourceRecord{
				Name:       hostName,
				Type:       TypeA,
				Class:      ClassIN,
				TTL:        hostTTL,
				CacheFlush: true,
				IP:         ip4,
			})
		} else {
			records = append(records, &ResourceRecord{
				Name:       hostName,
				Type:       TypeAAAA,
				Class:      ClassIN,
				TTL:        hostTTL,
				CacheFlush: true,
				IP:         ip,
			})
		}
	}

	return records
}

// probeService implements the probing sequence described in RFC 6762 §8.1.
//
// 1. Wait a random time [0, 250ms]
// 2. Send a probe (multicast query with authority records) 3 times, 250ms apart
// 3. If no conflict, mark as announced and send announcement
// 4. If conflict and we lose tiebreak (#2), rename and re-probe (#1)
func (s *Server) probeService(rs *registeredService) {
	s.mu.Lock()
	rs.state = stateProbing
	s.mu.Unlock()

	// Random initial delay [0, 250ms].
	delay := time.Duration(rand.IntN(250)) * time.Millisecond
	select {
	case <-s.ctx.Done():
		return
	case <-time.After(delay):
	}

	// Build probe messages.  For mDNS probing, we send a query for each unique
	// record name, with the records we intend to use in the authority section.
	probeMsg := s.buildProbeMessage(rs.records)

	// Send 3 probes, 250ms apart (RFC 6762 §8.1).
	for i := 0; i < int(DefaultProbeCount); i++ {
		data, err := probeMsg.Pack()
		if err != nil {
			s.log("failed to pack probe: %v", err)
			return
		}
		if err := s.conn.WriteMulticast(data); err != nil {
			s.log("failed to send probe: %v", err)
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

	// Wait one more probe interval for late conflict responses.
	select {
	case <-s.ctx.Done():
		return
	case <-time.After(DefaultProbeWait):
	}

	// Check if we lost a tiebreak during probing.
	s.mu.RLock()
	currentState := rs.state
	s.mu.RUnlock()

	if currentState == stateConflictLost {
		// #1: We lost the tiebreak — rename and re-probe.
		s.handleConflictRename(rs)
		return
	}

	// No conflict detected — announce the service.
	s.mu.Lock()
	rs.state = stateAnnounced
	close(rs.probeCh)
	s.mu.Unlock()

	s.announceService(rs)
}

// handleConflictRename renames a service that lost a naming conflict and
// re-probes with the new name (RFC 6762 §9).
func (s *Server) handleConflictRename(rs *registeredService) {
	s.mu.Lock()
	oldName := rs.instance.Name
	// BUG-6 fix: Extract existing numeric suffix (if any) and increment it,
	// instead of blindly appending " (2)" each time (which would produce
	// "Name (2) (2) (2)..." on repeated conflicts).
	rs.instance.Name = incrementNameSuffix(oldName)
	s.log("conflict resolution: renamed %q to %q", oldName, rs.instance.Name)

	// Regenerate records with the new name.
	rs.records = s.generateServiceRecords(rs.instance)

	// Reset state and re-probe.
	rs.state = stateIdle
	rs.probeCh = make(chan struct{})

	// Update service map key.
	oldKey := lowerName(oldName + "." + rs.instance.ServiceType())
	newKey := lowerName(normalizeName(rs.instance.InstanceName()))
	delete(s.services, oldKey)
	s.services[newKey] = rs
	s.mu.Unlock()

	go s.probeService(rs)
}

// incrementNameSuffix generates the next name in a conflict-rename sequence.
// "Service" → "Service (2)" → "Service (3)" → ...
// "Service (2)" → "Service (3)" (not "Service (2) (2)")
func incrementNameSuffix(name string) string {
	// Check if name already ends with " (N)" pattern.
	if idx := strings.LastIndex(name, " ("); idx > 0 {
		suffix := name[idx+2:]
		if strings.HasSuffix(suffix, ")") {
			numStr := suffix[:len(suffix)-1]
			if num, err := strconv.Atoi(numStr); err == nil && num >= 2 {
				return name[:idx] + " (" + strconv.Itoa(num+1) + ")"
			}
		}
	}
	return name + " (2)"
}

// buildProbeMessage creates the probe query for the given records.
func (s *Server) buildProbeMessage(records []*ResourceRecord) *Message {
	var questions []*Question
	var authorities []*ResourceRecord

	seen := make(map[string]bool)
	for _, rr := range records {
		ln := lowerName(rr.Name)
		if !seen[ln] {
			questions = append(questions, &Question{
				Name:  rr.Name,
				Type:  TypeAny,
				Class: ClassIN,
			})
			seen[ln] = true
		}
		authorities = append(authorities, rr)
	}

	return &Message{
		Header: Header{
			Flags:   0, // query
			QDCount: uint16(len(questions)),
			NSCount: uint16(len(authorities)),
		},
		Questions:   questions,
		Authorities: authorities,
	}
}

// announceService sends an unsolicited multicast response with all service records.
// Per RFC 6762 §8.3, the announcement is sent twice: once immediately and once
// after 1 second, to improve reliability.
func (s *Server) announceService(rs *registeredService) {
	s.log("announcing service: %s", rs.instance.InstanceName())

	// First announcement.
	s.sendResponseMulticast(rs.records)

	// Second announcement after 1 second (RFC 6762 §8.3).
	go func() {
		select {
		case <-s.ctx.Done():
		case <-time.After(DefaultAnnounceTTL):
			s.sendResponseMulticast(rs.records)
		}
	}()
}

// Services returns information about all registered services.
func (s *Server) Services() []*ServiceInstance {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ServiceInstance
	for _, rs := range s.services {
		result = append(result, rs.instance)
	}
	return result
}

