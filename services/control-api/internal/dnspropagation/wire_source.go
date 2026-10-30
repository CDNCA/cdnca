package dnspropagation

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	defaultWireResponseBytes = 16 * 1024
	maximumWireResponseBytes = 65535
	maximumWireRecords       = 256
	ednsPayloadBytes         = 1232
	ednsDNSSECOK             = uint32(1 << 15)
	ednsExtendedError        = uint16(15)
	edeStaleAnswer           = uint16(3)
	edeDNSSECBogus           = uint16(6)
)

var errInvalidWireResponse = errors.New("invalid dns wire response")

// errAddressFamilyUnavailable is returned without dialing when the host has
// no route for the endpoint's address family (for example AAAA name servers
// on a control host without IPv6).
var errAddressFamilyUnavailable = errors.New("dns endpoint address family unavailable on this host")

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type WireSourceConfig struct {
	Bootstrap            []Resolver
	DialContext          DialContextFunc
	QueryTimeout         time.Duration
	MaximumResponseBytes int
	Now                  func() time.Time
	// FamilyAvailable, when set, is asked before dialing a discovered
	// authority; false skips it with errAddressFamilyUnavailable. Production
	// uses LocalAddressFamilies().
	FamilyAvailable func(netip.Addr) bool
}

type WireSource struct {
	bootstrap            []Resolver
	bootstrapIDs         map[string]struct{}
	dialContext          DialContextFunc
	queryTimeout         time.Duration
	maximumResponseBytes int
	now                  func() time.Time
	familyAvailable      func(netip.Addr) bool
}

// LocalAddressFamilies reports whether the host has a route for an address's
// family. It "connects" an unsent UDP socket to a public address of that
// family (route lookup only, no packet), caching each answer for a minute.
func LocalAddressFamilies() func(netip.Addr) bool {
	var mu sync.Mutex
	type probe struct {
		available bool
		at        time.Time
	}
	cache := map[bool]probe{}
	return func(address netip.Addr) bool {
		v6 := address.Unmap().Is6()
		mu.Lock()
		defer mu.Unlock()
		if cached, ok := cache[v6]; ok && time.Since(cached.at) < time.Minute {
			return cached.available
		}
		network, target := "udp4", "192.0.2.1:53"
		if v6 {
			network, target = "udp6", "[2001:db8::1]:53"
		}
		available := true
		if connection, err := net.Dial(network, target); err != nil {
			available = false
		} else {
			_ = connection.Close()
		}
		cache[v6] = probe{available: available, at: time.Now()}
		return available
	}
}

type wireDNSResponse struct {
	header      dnsmessage.Header
	answers     []dnsmessage.Resource
	authorities []dnsmessage.Resource
	additionals []dnsmessage.Resource
}

func NewWireSource(config WireSourceConfig) (*WireSource, error) {
	maximumBytes := config.MaximumResponseBytes
	if maximumBytes == 0 {
		maximumBytes = defaultWireResponseBytes
	}
	if len(config.Bootstrap) == 0 || config.DialContext == nil || config.QueryTimeout <= 0 ||
		config.QueryTimeout > 30*time.Second || maximumBytes < 512 || maximumBytes > maximumWireResponseBytes ||
		config.Now == nil {
		return nil, ErrInvalidInput
	}
	bootstrapIDs := make(map[string]struct{}, len(config.Bootstrap))
	bootstrap := make([]Resolver, 0, len(config.Bootstrap))
	for _, resolver := range config.Bootstrap {
		if !validText(resolver.Name, 255) {
			return nil, ErrInvalidInput
		}
		endpoint, err := parseCanonicalEndpoint(resolver.ID)
		if err != nil || endpoint.Port() == 0 {
			return nil, ErrInvalidInput
		}
		if _, duplicate := bootstrapIDs[resolver.ID]; duplicate {
			return nil, ErrInvalidInput
		}
		bootstrapIDs[resolver.ID] = struct{}{}
		bootstrap = append(bootstrap, resolver)
	}
	return &WireSource{
		bootstrap: bootstrap, bootstrapIDs: bootstrapIDs, dialContext: config.DialContext,
		queryTimeout: config.QueryTimeout, maximumResponseBytes: maximumBytes, now: config.Now,
		familyAvailable: config.FamilyAvailable,
	}, nil
}

func (source *WireSource) Discover(ctx context.Context, operationID, zone string) (Delegation, error) {
	zoneName, err := canonicalWireName(zone)
	if source == nil || ctx == nil || ctx.Err() != nil || !validText(operationID, 256) || err != nil {
		if ctx != nil && ctx.Err() != nil {
			return Delegation{}, ctx.Err()
		}
		return Delegation{}, ErrInvalidInput
	}

	var response wireDNSResponse
	var bootstrapErr error
	for _, bootstrap := range source.bootstrap {
		response, bootstrapErr = source.query(ctx, bootstrap.ID, zoneName, dnsmessage.TypeNS)
		if bootstrapErr == nil && response.header.RCode == dnsmessage.RCodeSuccess {
			break
		}
	}
	if bootstrapErr != nil || response.header.RCode != dnsmessage.RCodeSuccess {
		if bootstrapErr != nil {
			return Delegation{}, bootstrapErr
		}
		return Delegation{}, errInvalidWireResponse
	}

	authorityNames := make(map[string]struct{})
	for _, resource := range append(append([]dnsmessage.Resource(nil), response.answers...), response.authorities...) {
		if resource.Header.Name.String() != zoneName {
			continue
		}
		if ns, ok := resource.Body.(*dnsmessage.NSResource); ok {
			authorityNames[strings.ToLower(ns.NS.String())] = struct{}{}
		}
	}
	if len(authorityNames) == 0 {
		return Delegation{}, errInvalidWireResponse
	}

	glue := make(map[string][]netip.Addr, len(authorityNames))
	for _, resource := range response.additionals {
		owner := strings.ToLower(resource.Header.Name.String())
		if _, authority := authorityNames[owner]; !authority {
			continue
		}
		if address, ok := wireResourceAddress(resource); ok {
			glue[owner] = append(glue[owner], address)
		}
	}
	for authorityName := range authorityNames {
		if len(glue[authorityName]) != 0 {
			continue
		}
		addresses, lookupErr := source.lookupAuthorityAddresses(ctx, authorityName)
		if lookupErr != nil {
			return Delegation{}, lookupErr
		}
		glue[authorityName] = addresses
	}

	authorities := make([]Resolver, 0, len(authorityNames))
	seen := make(map[string]struct{})
	for authorityName := range authorityNames {
		if len(glue[authorityName]) == 0 {
			return Delegation{}, errInvalidWireResponse
		}
		for _, address := range glue[authorityName] {
			endpoint := netip.AddrPortFrom(address.Unmap(), 53)
			if !safeDynamicEndpoint(endpoint) {
				return Delegation{}, ErrInvalidInput
			}
			id := endpoint.String()
			if _, duplicate := seen[id]; duplicate {
				continue
			}
			seen[id] = struct{}{}
			authorities = append(authorities, Resolver{ID: id, Name: authorityName})
		}
	}
	sort.Slice(authorities, func(left, right int) bool {
		if authorities[left].Name == authorities[right].Name {
			return authorities[left].ID < authorities[right].ID
		}
		return authorities[left].Name < authorities[right].Name
	})
	return Delegation{Zone: zoneName, Signed: response.header.AuthenticData, Authorities: authorities}, nil
}

func (source *WireSource) Observe(ctx context.Context, operationID string, resolver Resolver, name string,
	types []dnscheck.RecordType) (Observation, error) {
	owner, err := canonicalWireName(name)
	if source == nil || ctx == nil || ctx.Err() != nil || !validText(operationID, 256) ||
		!validText(resolver.Name, 255) || err != nil || len(types) == 0 || len(types) > 4 {
		if ctx != nil && ctx.Err() != nil {
			return Observation{}, ctx.Err()
		}
		return Observation{}, ErrInvalidInput
	}
	endpoint, err := parseCanonicalEndpoint(resolver.ID)
	if err != nil {
		return Observation{}, ErrInvalidInput
	}
	role := RoleAuthoritative
	if _, configured := source.bootstrapIDs[resolver.ID]; configured {
		role = RolePublicRecursive
	} else if !safeDynamicEndpoint(endpoint) {
		return Observation{}, ErrInvalidInput
	} else if source.familyAvailable != nil && !source.familyAvailable(endpoint.Addr()) {
		return Observation{}, errAddressFamilyUnavailable
	}

	seenTypes := make(map[dnscheck.RecordType]struct{}, len(types))
	sets := make(map[dnscheck.RecordType]map[string]struct{}, len(types))
	cnameTargets := make(map[string]struct{})
	status := ResponseStatus("")
	dnssec := DNSSECSecure
	minimumTTL := time.Duration(0)
	minimumNegativeTTL := time.Duration(0)
	stale := false
	for _, recordType := range types {
		if !supportedType(recordType) {
			return Observation{}, ErrInvalidInput
		}
		if _, duplicate := seenTypes[recordType]; duplicate {
			return Observation{}, ErrInvalidInput
		}
		seenTypes[recordType] = struct{}{}
		response, queryErr := source.query(ctx, resolver.ID, owner, dnsmessage.Type(recordType))
		if queryErr != nil {
			return Observation{}, queryErr
		}
		queryStatus, statusErr := responseStatus(response)
		if statusErr != nil {
			return Observation{}, statusErr
		}
		if status == "" {
			status = queryStatus
		} else if status != queryStatus && status != ResponseAnswer && queryStatus != ResponseAnswer {
			return Observation{}, errInvalidWireResponse
		} else if queryStatus == ResponseAnswer {
			status = ResponseAnswer
		}
		if queryStatus == ResponseSERVFAIL {
			dnssec = DNSSECIndeterminate
		} else if !response.header.AuthenticData && dnssec != DNSSECBogus {
			dnssec = DNSSECInsecure
		}
		responseStale, bogus := extendedDNSError(response.additionals)
		stale = stale || responseStale
		if bogus {
			dnssec = DNSSECBogus
		}
		for _, resource := range response.answers {
			value, parsedType, ok := wireResourceValue(resource)
			if !ok {
				continue
			}
			if sets[parsedType] == nil {
				sets[parsedType] = make(map[string]struct{})
			}
			sets[parsedType][value] = struct{}{}
			if parsedType == dnscheck.RecordCNAME {
				cnameTargets[value] = struct{}{}
			}
			ttl := time.Duration(resource.Header.TTL) * time.Second
			minimumTTL = minimumPositiveDuration(minimumTTL, ttl)
		}
		for _, resource := range response.authorities {
			soa, ok := resource.Body.(*dnsmessage.SOAResource)
			if !ok {
				continue
			}
			negative := resource.Header.TTL
			if soa.MinTTL < negative {
				negative = soa.MinTTL
			}
			minimumNegativeTTL = minimumPositiveDuration(minimumNegativeTTL, time.Duration(negative)*time.Second)
		}
	}

	records := make([]RRSet, 0, len(sets))
	for recordType, values := range sets {
		ordered := make([]string, 0, len(values))
		for value := range values {
			ordered = append(ordered, value)
		}
		sort.Strings(ordered)
		records = append(records, RRSet{Type: recordType, Values: ordered})
	}
	sort.Slice(records, func(left, right int) bool { return records[left].Type < records[right].Type })
	chain := make([]string, 0, len(cnameTargets))
	for target := range cnameTargets {
		chain = append(chain, target)
	}
	sort.Strings(chain)
	return Observation{
		OperationID: operationID, Role: role, ResolverID: resolver.ID, Status: status, DNSSEC: dnssec,
		Records: records, CNAMEChain: chain, TTL: minimumTTL, NegativeTTL: minimumNegativeTTL,
		ObservedAt: source.now().UTC(), Stale: stale,
	}, nil
}

func (source *WireSource) lookupAuthorityAddresses(ctx context.Context, name string) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, 2)
	for _, recordType := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		var response wireDNSResponse
		var err error
		for _, bootstrap := range source.bootstrap {
			response, err = source.query(ctx, bootstrap.ID, name, recordType)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, err
		}
		if response.header.RCode != dnsmessage.RCodeSuccess {
			return nil, errInvalidWireResponse
		}
		for _, resource := range response.answers {
			if resource.Header.Name.String() != name {
				continue
			}
			if address, ok := wireResourceAddress(resource); ok {
				addresses = append(addresses, address)
			}
		}
	}
	return addresses, nil
}

func (source *WireSource) query(ctx context.Context, address, name string, recordType dnsmessage.Type) (wireDNSResponse, error) {
	queryID, err := randomWireQueryID()
	if err != nil {
		return wireDNSResponse{}, err
	}
	payload, err := buildWireQuery(queryID, name, recordType)
	if err != nil {
		return wireDNSResponse{}, ErrInvalidInput
	}
	message, err := source.exchange(ctx, "udp", address, payload)
	if err != nil {
		return wireDNSResponse{}, err
	}
	response, err := parseWireResponse(message, source.maximumResponseBytes, queryID, name, recordType)
	if err != nil {
		return wireDNSResponse{}, err
	}
	if response.header.Truncated {
		message, err = source.exchange(ctx, "tcp", address, payload)
		if err != nil {
			return wireDNSResponse{}, err
		}
		response, err = parseWireResponse(message, source.maximumResponseBytes, queryID, name, recordType)
		if err != nil || response.header.Truncated {
			return wireDNSResponse{}, errInvalidWireResponse
		}
	}
	return response, nil
}

func (source *WireSource) exchange(parent context.Context, network, address string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, source.queryTimeout)
	defer cancel()
	connection, err := source.dialContext(ctx, network, address)
	if err != nil {
		return nil, mapWireError(ctx, err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stopCancellation()

	if network == "tcp" {
		framed := make([]byte, 2, len(payload)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(payload)))
		framed = append(framed, payload...)
		if err := writeWirePayload(connection, framed); err != nil {
			return nil, mapWireError(ctx, err)
		}
		lengthPrefix := make([]byte, 2)
		if _, err := io.ReadFull(connection, lengthPrefix); err != nil {
			return nil, mapWireError(ctx, err)
		}
		length := int(binary.BigEndian.Uint16(lengthPrefix))
		if length < 12 || length > source.maximumResponseBytes {
			return nil, errInvalidWireResponse
		}
		response := make([]byte, length)
		if _, err := io.ReadFull(connection, response); err != nil {
			return nil, mapWireError(ctx, err)
		}
		return response, nil
	}
	if err := writeWirePayload(connection, payload); err != nil {
		return nil, mapWireError(ctx, err)
	}
	response := make([]byte, source.maximumResponseBytes+1)
	read, err := connection.Read(response)
	if err != nil {
		return nil, mapWireError(ctx, err)
	}
	if read > source.maximumResponseBytes {
		return nil, errInvalidWireResponse
	}
	return response[:read], nil
}

func buildWireQuery(id uint16, name string, recordType dnsmessage.Type) ([]byte, error) {
	parsedName, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{Name: parsedName, Type: recordType, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := builder.StartAdditionals(); err != nil {
		return nil, err
	}
	root, _ := dnsmessage.NewName(".")
	if err := builder.OPTResource(dnsmessage.ResourceHeader{Name: root, Class: dnsmessage.Class(ednsPayloadBytes), TTL: ednsDNSSECOK}, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func parseWireResponse(message []byte, maximumBytes int, id uint16, name string,
	recordType dnsmessage.Type) (wireDNSResponse, error) {
	if len(message) < 12 || len(message) > maximumBytes {
		return wireDNSResponse{}, errInvalidWireResponse
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil || !header.Response || header.OpCode != 0 || header.ID != id {
		return wireDNSResponse{}, errInvalidWireResponse
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Name.String() != name ||
		questions[0].Type != recordType || questions[0].Class != dnsmessage.ClassINET {
		return wireDNSResponse{}, errInvalidWireResponse
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return wireDNSResponse{}, errInvalidWireResponse
	}
	authorities, err := parser.AllAuthorities()
	if err != nil {
		return wireDNSResponse{}, errInvalidWireResponse
	}
	additionals, err := parser.AllAdditionals()
	if err != nil || len(answers)+len(authorities)+len(additionals) > maximumWireRecords {
		return wireDNSResponse{}, errInvalidWireResponse
	}
	return wireDNSResponse{header: header, answers: answers, authorities: authorities, additionals: additionals}, nil
}

func responseStatus(response wireDNSResponse) (ResponseStatus, error) {
	switch response.header.RCode {
	case dnsmessage.RCodeSuccess:
		if len(response.answers) == 0 {
			return ResponseNODATA, nil
		}
		return ResponseAnswer, nil
	case dnsmessage.RCodeNameError:
		return ResponseNXDOMAIN, nil
	case dnsmessage.RCodeServerFailure:
		return ResponseSERVFAIL, nil
	default:
		return "", errInvalidWireResponse
	}
}

func wireResourceAddress(resource dnsmessage.Resource) (netip.Addr, bool) {
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(body.A), true
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(body.AAAA).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

func wireResourceValue(resource dnsmessage.Resource) (string, dnscheck.RecordType, bool) {
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(body.A).String(), dnscheck.RecordA, true
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(body.AAAA).String(), dnscheck.RecordAAAA, true
	case *dnsmessage.CNAMEResource:
		return strings.ToLower(body.CNAME.String()), dnscheck.RecordCNAME, true
	case *dnsmessage.TXTResource:
		return strings.Join(body.TXT, ""), dnscheck.RecordTXT, true
	default:
		return "", 0, false
	}
}

func extendedDNSError(resources []dnsmessage.Resource) (stale, bogus bool) {
	for _, resource := range resources {
		opt, ok := resource.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, option := range opt.Options {
			if option.Code != ednsExtendedError || len(option.Data) < 2 {
				continue
			}
			switch binary.BigEndian.Uint16(option.Data[:2]) {
			case edeStaleAnswer:
				stale = true
			case edeDNSSECBogus:
				bogus = true
			}
		}
	}
	return stale, bogus
}

func parseCanonicalEndpoint(value string) (netip.AddrPort, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return netip.AddrPort{}, ErrInvalidInput
	}
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.String() != value || !endpoint.Addr().IsValid() || endpoint.Port() == 0 {
		return netip.AddrPort{}, ErrInvalidInput
	}
	return endpoint, nil
}

func safeDynamicEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr().Unmap()
	return endpoint.Port() == 53 && address.IsValid() && address.IsGlobalUnicast() &&
		!address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() &&
		!address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified()
}

func canonicalWireName(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", ErrInvalidInput
	}
	name, err := dnsmessage.NewName(value)
	if err != nil {
		return "", ErrInvalidInput
	}
	canonical := strings.ToLower(name.String())
	if canonical != value {
		return "", ErrInvalidInput
	}
	return canonical, nil
}

func minimumPositiveDuration(current, candidate time.Duration) time.Duration {
	if candidate <= 0 || current != 0 && current <= candidate {
		return current
	}
	return candidate
}

func randomWireQueryID() (uint16, error) {
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, fmt.Errorf("dns query id: %w", err)
	}
	return binary.BigEndian.Uint16(value[:]), nil
}

func writeWirePayload(connection net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := connection.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func mapWireError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

var _ Source = (*WireSource)(nil)
