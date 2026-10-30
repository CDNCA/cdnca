package dnspropagation

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

const (
	wireTypeNS  = uint16(2)
	wireTypeOPT = uint16(41)
)

type wireHandler func(network string, query []byte) ([]byte, error)

type wireDialCall struct {
	network string
	address string
	conn    *scriptedWireConn
}

type scriptedWireDialer struct {
	mu       sync.Mutex
	handlers map[string]wireHandler
	calls    []wireDialCall
}

func (dialer *scriptedWireDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	handler, ok := dialer.handlers[address]
	if !ok {
		return nil, errors.New("scripted dial rejected unregistered endpoint: " + address)
	}
	connection := &scriptedWireConn{network: network, handler: handler}
	dialer.calls = append(dialer.calls, wireDialCall{network: network, address: address, conn: connection})
	return connection, nil
}

func (dialer *scriptedWireDialer) snapshot() []wireDialCall {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]wireDialCall(nil), dialer.calls...)
}

type scriptedWireConn struct {
	mu             sync.Mutex
	network        string
	handler        wireHandler
	response       *bytes.Reader
	readErr        error
	request        []byte
	deadline       time.Time
	sawTCPFraming  bool
	responseLoaded bool
}

func (connection *scriptedWireConn) Read(payload []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.readErr != nil {
		return 0, connection.readErr
	}
	if connection.response == nil {
		return 0, io.EOF
	}
	return connection.response.Read(payload)
}

func (connection *scriptedWireConn) Write(payload []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.responseLoaded {
		return 0, errors.New("scripted connection received a second DNS request")
	}
	raw := append([]byte(nil), payload...)
	if connection.network == "tcp" {
		if len(raw) < 2 || int(binary.BigEndian.Uint16(raw[:2])) != len(raw)-2 {
			return 0, errors.New("DNS TCP request is not length framed")
		}
		connection.sawTCPFraming = true
		raw = raw[2:]
	}
	connection.request = append([]byte(nil), raw...)
	response, err := connection.handler(connection.network, raw)
	if err != nil {
		connection.readErr = err
		connection.responseLoaded = true
		return len(payload), nil
	}
	if connection.network == "tcp" {
		framed := make([]byte, 2, len(response)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(response)))
		response = append(framed, response...)
	}
	connection.response = bytes.NewReader(response)
	connection.responseLoaded = true
	return len(payload), nil
}

func (connection *scriptedWireConn) Close() error         { return nil }
func (connection *scriptedWireConn) LocalAddr() net.Addr  { return wireAddr("local") }
func (connection *scriptedWireConn) RemoteAddr() net.Addr { return wireAddr("remote") }
func (connection *scriptedWireConn) SetReadDeadline(deadline time.Time) error {
	return connection.SetDeadline(deadline)
}
func (connection *scriptedWireConn) SetWriteDeadline(deadline time.Time) error {
	return connection.SetDeadline(deadline)
}
func (connection *scriptedWireConn) SetDeadline(deadline time.Time) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.deadline = deadline
	return nil
}

type wireAddr string

func (address wireAddr) Network() string { return "scripted" }
func (address wireAddr) String() string  { return string(address) }

type wireQuestion struct {
	id      uint16
	flags   uint16
	name    string
	typeID  uint16
	end     int
	request []byte
}

func parseWireQuestion(message []byte) (wireQuestion, error) {
	if len(message) < 17 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return wireQuestion{}, errors.New("invalid DNS question")
	}
	name, next, err := parseTestWireName(message, 12)
	if err != nil || next+4 > len(message) || binary.BigEndian.Uint16(message[next+2:next+4]) != 1 {
		return wireQuestion{}, errors.New("invalid DNS question")
	}
	return wireQuestion{
		id: binary.BigEndian.Uint16(message[:2]), flags: binary.BigEndian.Uint16(message[2:4]),
		name: name, typeID: binary.BigEndian.Uint16(message[next : next+2]), end: next + 4,
		request: message,
	}, nil
}

func parseTestWireName(message []byte, start int) (string, int, error) {
	labels := make([]byte, 0, 64)
	for position := start; ; {
		if position >= len(message) {
			return "", 0, io.ErrUnexpectedEOF
		}
		length := int(message[position])
		position++
		if length == 0 {
			if len(labels) == 0 {
				return ".", position, nil
			}
			return string(labels) + ".", position, nil
		}
		if length > 63 || position+length > len(message) {
			return "", 0, errors.New("invalid DNS name")
		}
		if len(labels) > 0 {
			labels = append(labels, '.')
		}
		labels = append(labels, message[position:position+length]...)
		position += length
	}
}

func requireEDNSDO(query wireQuestion) error {
	if query.flags&0x0100 == 0 || binary.BigEndian.Uint16(query.request[10:12]) != 1 {
		return errors.New("DNS request did not include recursion desired and one EDNS record")
	}
	if query.end+11 > len(query.request) || query.request[query.end] != 0 ||
		binary.BigEndian.Uint16(query.request[query.end+1:query.end+3]) != wireTypeOPT ||
		binary.BigEndian.Uint32(query.request[query.end+5:query.end+9])&0x00008000 == 0 {
		return errors.New("DNS request did not set EDNS DO")
	}
	return nil
}

func wireResponse(query wireQuestion, flags uint16, answers, authority, additional [][]byte) []byte {
	response := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(response[:2], query.id)
	binary.BigEndian.PutUint16(response[2:4], flags|0x8000)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(response[8:10], uint16(len(authority)))
	binary.BigEndian.PutUint16(response[10:12], uint16(len(additional)))
	response = append(response, query.request[12:query.end]...)
	for _, section := range [][][]byte{answers, authority, additional} {
		for _, record := range section {
			response = append(response, record...)
		}
	}
	return response
}

func wireResource(owner string, typeID uint16, ttl uint32, data []byte) []byte {
	result := wireName(owner)
	result = binary.BigEndian.AppendUint16(result, typeID)
	result = binary.BigEndian.AppendUint16(result, 1)
	result = binary.BigEndian.AppendUint32(result, ttl)
	result = binary.BigEndian.AppendUint16(result, uint16(len(data)))
	return append(result, data...)
}

func wireName(name string) []byte {
	if name == "." {
		return []byte{0}
	}
	name = name[:len(name)-1]
	result := make([]byte, 0, len(name)+2)
	start := 0
	for index := 0; index <= len(name); index++ {
		if index == len(name) || name[index] == '.' {
			result = append(result, byte(index-start))
			result = append(result, name[start:index]...)
			start = index + 1
		}
	}
	return append(result, 0)
}

func wireA(address string) []byte {
	parsed := netip.MustParseAddr(address).As4()
	return parsed[:]
}

func wireAAAA(address string) []byte {
	parsed := netip.MustParseAddr(address).As16()
	return parsed[:]
}

func wireTXT(value string) []byte {
	return append([]byte{byte(len(value))}, value...)
}

func wireSOA(minimum uint32) []byte {
	result := append(wireName("ns1.example.test."), wireName("hostmaster.example.test.")...)
	for _, value := range []uint32{1, 60, 60, 3600, minimum} {
		result = binary.BigEndian.AppendUint32(result, value)
	}
	return result
}

func wireEDEStale() []byte {
	data := binary.BigEndian.AppendUint16(nil, 15)
	data = binary.BigEndian.AppendUint16(data, 2)
	data = binary.BigEndian.AppendUint16(data, 3)
	result := []byte{0}
	result = binary.BigEndian.AppendUint16(result, wireTypeOPT)
	result = binary.BigEndian.AppendUint16(result, 1232)
	result = binary.BigEndian.AppendUint32(result, 0)
	result = binary.BigEndian.AppendUint16(result, uint16(len(data)))
	return append(result, data...)
}

func newScriptedWireSource(t *testing.T, dialer *scriptedWireDialer, bootstrap []Resolver) *WireSource {
	t.Helper()
	source, err := NewWireSource(WireSourceConfig{
		Bootstrap: bootstrap, DialContext: dialer.DialContext,
		QueryTimeout: 100 * time.Millisecond, MaximumResponseBytes: 4096,
		Now: func() time.Time { return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewWireSource() error = %v", err)
	}
	return source
}

func TestNewWireSourceRequiresCanonicalLiteralBootstrapAllowlist(t *testing.T) {
	t.Parallel()
	valid := Resolver{ID: "8.8.8.8:53", Name: "bootstrap-a"}
	tests := []struct {
		name   string
		config WireSourceConfig
	}{
		{name: "hostname endpoint", config: WireSourceConfig{Bootstrap: []Resolver{{ID: "dns.google:53", Name: "bootstrap"}}}},
		{name: "noncanonical port", config: WireSourceConfig{Bootstrap: []Resolver{{ID: "8.8.8.8:053", Name: "bootstrap"}}}},
		{name: "unbracketed IPv6", config: WireSourceConfig{Bootstrap: []Resolver{{ID: "2001:4860:4860::8888:53", Name: "bootstrap"}}}},
		{name: "duplicate literal identity", config: WireSourceConfig{Bootstrap: []Resolver{valid, {ID: valid.ID, Name: "alias"}}}},
		{name: "empty bootstrap", config: WireSourceConfig{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := test.config
			config.DialContext = (&scriptedWireDialer{}).DialContext
			config.QueryTimeout = time.Second
			config.MaximumResponseBytes = 512
			config.Now = time.Now
			if _, err := NewWireSource(config); err == nil {
				t.Fatal("NewWireSource() error = nil, want fail-closed bootstrap validation")
			}
		})
	}
}

func TestWireSourceDiscoversNSGlueAndObservesDNSSECMultiTypeChain(t *testing.T) {
	t.Parallel()
	bootstrap := Resolver{ID: "8.8.8.8:53", Name: "bootstrap-a"}
	authorityAddress := "203.0.113.53:53"
	authorityName := "ns1.example.test."
	owner := "_acme-challenge.www.example.test."
	target := "_acme-challenge.delegate.example.test."
	operationID := "operation-wire-source"
	dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
	dialer.handlers[bootstrap.ID] = func(_ string, raw []byte) ([]byte, error) {
		query, err := parseWireQuestion(raw)
		if err != nil || requireEDNSDO(query) != nil || query.name != "example.test." || query.typeID != wireTypeNS {
			return nil, errors.New("unexpected authoritative discovery query")
		}
		return wireResponse(query, 0x0020,
			[][]byte{wireResource(query.name, wireTypeNS, 300, wireName(authorityName))}, nil,
			[][]byte{wireResource(authorityName, uint16(dnscheck.RecordA), 300, wireA("203.0.113.53"))}), nil
	}
	dialer.handlers[authorityAddress] = func(_ string, raw []byte) ([]byte, error) {
		query, err := parseWireQuestion(raw)
		if err != nil || requireEDNSDO(query) != nil || query.name != owner {
			return nil, errors.New("unexpected authority observation query")
		}
		answers := [][]byte{wireResource(owner, uint16(dnscheck.RecordCNAME), 120, wireName(target))}
		switch dnscheck.RecordType(query.typeID) {
		case dnscheck.RecordA:
			answers = append(answers, wireResource(target, query.typeID, 120, wireA("192.0.2.80")))
		case dnscheck.RecordAAAA:
			answers = append(answers, wireResource(target, query.typeID, 120, wireAAAA("2001:db8::80")))
		case dnscheck.RecordTXT:
			answers = append(answers, wireResource(target, query.typeID, 120, wireTXT("acme-proof")))
		case dnscheck.RecordCNAME:
		default:
			return nil, errors.New("unexpected observation record type")
		}
		return wireResponse(query, 0x0420, answers, nil, nil), nil
	}
	source := newScriptedWireSource(t, dialer, []Resolver{bootstrap})
	delegation, err := source.Discover(context.Background(), operationID, "example.test.")
	if err != nil || delegation.Zone != "example.test." || !delegation.Signed ||
		len(delegation.Authorities) != 1 || delegation.Authorities[0].ID != authorityAddress ||
		delegation.Authorities[0].Name != authorityName {
		t.Fatalf("Discover() = (%#v, %v), want signed glue authority", delegation, err)
	}

	observation, err := source.Observe(context.Background(), operationID, delegation.Authorities[0], owner,
		[]dnscheck.RecordType{dnscheck.RecordA, dnscheck.RecordAAAA, dnscheck.RecordTXT, dnscheck.RecordCNAME})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if observation.OperationID != operationID || observation.Role != RoleAuthoritative || observation.ResolverID != authorityAddress ||
		observation.Status != ResponseAnswer || observation.DNSSEC != DNSSECSecure || observation.TTL != 2*time.Minute ||
		!slices.Contains(observation.CNAMEChain, target) {
		t.Fatalf("Observe() = %#v, want secure authoritative CNAME result", observation)
	}
	for _, recordType := range []dnscheck.RecordType{dnscheck.RecordA, dnscheck.RecordAAAA, dnscheck.RecordTXT, dnscheck.RecordCNAME} {
		if !slices.ContainsFunc(observation.Records, func(set RRSet) bool { return set.Type == recordType && len(set.Values) > 0 }) {
			t.Fatalf("records = %#v, missing %s", observation.Records, recordType)
		}
	}
	for _, call := range dialer.snapshot() {
		if call.address != bootstrap.ID && call.address != authorityAddress {
			t.Fatalf("unexpected dial target %q", call.address)
		}
	}
}

func TestWireSourceResolvesMissingGlueOnlyThroughBootstrap(t *testing.T) {
	t.Parallel()
	bootstrap := Resolver{ID: "1.1.1.1:53", Name: "bootstrap-a"}
	authorityName := "ns1.example.test."
	dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
	dialer.handlers[bootstrap.ID] = func(_ string, raw []byte) ([]byte, error) {
		query, err := parseWireQuestion(raw)
		if err != nil || requireEDNSDO(query) != nil {
			return nil, errors.New("invalid bootstrap query")
		}
		switch dnscheck.RecordType(query.typeID) {
		case dnscheck.RecordType(wireTypeNS):
			return wireResponse(query, 0x0020,
				[][]byte{wireResource(query.name, wireTypeNS, 300, wireName(authorityName))}, nil, nil), nil
		case dnscheck.RecordA:
			if query.name != authorityName {
				return nil, errors.New("bootstrap A lookup used wrong NS name")
			}
			return wireResponse(query, 0x0020,
				[][]byte{wireResource(authorityName, query.typeID, 300, wireA("203.0.113.54"))}, nil, nil), nil
		case dnscheck.RecordAAAA:
			return wireResponse(query, 0x0020, nil,
				[][]byte{wireResource("example.test.", uint16(dnscheck.RecordSOA), 60, wireSOA(30))}, nil), nil
		default:
			return nil, errors.New("unexpected bootstrap query type")
		}
	}
	source := newScriptedWireSource(t, dialer, []Resolver{bootstrap})
	delegation, err := source.Discover(context.Background(), "operation-missing-glue", "example.test.")
	if err != nil || len(delegation.Authorities) != 1 || delegation.Authorities[0].ID != "203.0.113.54:53" {
		t.Fatalf("Discover() = (%#v, %v), want bootstrap-resolved missing glue", delegation, err)
	}
	calls := dialer.snapshot()
	if len(calls) < 2 {
		t.Fatalf("bootstrap dial count = %d, want NS plus missing-glue address lookup", len(calls))
	}
	for _, call := range calls {
		if call.address != bootstrap.ID {
			t.Fatalf("missing glue dialed %q directly, want bootstrap %q", call.address, bootstrap.ID)
		}
	}
}

func TestWireSourceRejectsNonPublicDynamicAuthorityBeforeDial(t *testing.T) {
	t.Parallel()
	addresses := []string{"10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1", "ff02::1", "::"}
	for _, address := range addresses {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			bootstrap := Resolver{ID: "9.9.9.9:53", Name: "bootstrap"}
			dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
			dialer.handlers[bootstrap.ID] = func(_ string, raw []byte) ([]byte, error) {
				query, err := parseWireQuestion(raw)
				if err != nil {
					return nil, err
				}
				var glue []byte
				typeID := uint16(dnscheck.RecordA)
				if netip.MustParseAddr(address).Is6() {
					typeID, glue = uint16(dnscheck.RecordAAAA), wireAAAA(address)
				} else {
					glue = wireA(address)
				}
				return wireResponse(query, 0x0020,
					[][]byte{wireResource(query.name, wireTypeNS, 300, wireName("ns.bad.example.test."))}, nil,
					[][]byte{wireResource("ns.bad.example.test.", typeID, 300, glue)}), nil
			}
			source := newScriptedWireSource(t, dialer, []Resolver{bootstrap})
			if delegation, err := source.Discover(context.Background(), "operation-rejected-glue", "example.test."); err == nil {
				t.Fatalf("Discover() = %#v, want rejection for dynamic address %s", delegation, address)
			}
			for _, call := range dialer.snapshot() {
				if call.address != bootstrap.ID {
					t.Fatalf("rejected dynamic authority was dialed: %#v", call)
				}
			}
		})
	}
}

func TestWireSourceObserveRejectsHostnameAndUntrustedLiteralWithoutDial(t *testing.T) {
	t.Parallel()
	bootstrap := Resolver{ID: "8.8.4.4:53", Name: "bootstrap"}
	dialer := &scriptedWireDialer{handlers: map[string]wireHandler{bootstrap.ID: func(_ string, raw []byte) ([]byte, error) {
		query, err := parseWireQuestion(raw)
		if err != nil {
			return nil, err
		}
		return wireResponse(query, 0x8020, nil, nil, nil), nil
	}}}
	source := newScriptedWireSource(t, dialer, []Resolver{bootstrap})
	for _, resolver := range []Resolver{
		{ID: "ns.attacker.test:53", Name: "hostname"},
		{ID: "127.0.0.1:53", Name: "loopback"},
		{ID: "10.0.0.1:53", Name: "private"},
	} {
		if _, err := source.Observe(context.Background(), "operation-rejected-observe", resolver, "www.example.test.", []dnscheck.RecordType{dnscheck.RecordA}); err == nil {
			t.Fatalf("Observe(%q) error = nil, want SSRF rejection", resolver.ID)
		}
	}
	if calls := dialer.snapshot(); len(calls) != 0 {
		t.Fatalf("rejected Observe() calls dialed network: %#v", calls)
	}
}

func TestWireSourceUDPTruncationFallsBackToFramedTCP(t *testing.T) {
	t.Parallel()
	resolver := Resolver{ID: "8.8.8.8:53", Name: "recursive"}
	dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
	dialer.handlers[resolver.ID] = func(network string, raw []byte) ([]byte, error) {
		query, err := parseWireQuestion(raw)
		if err != nil || requireEDNSDO(query) != nil {
			return nil, errors.New("invalid truncated fallback query")
		}
		if network == "udp" {
			return wireResponse(query, 0x0200, nil, nil, nil), nil
		}
		return wireResponse(query, 0x0020,
			[][]byte{wireResource(query.name, query.typeID, 60, wireA("192.0.2.80"))}, nil, nil), nil
	}
	source := newScriptedWireSource(t, dialer, []Resolver{resolver})
	observation, err := source.Observe(context.Background(), "operation-tcp-fallback", resolver, "www.example.test.", []dnscheck.RecordType{dnscheck.RecordA})
	if err != nil || observation.Status != ResponseAnswer {
		t.Fatalf("Observe() = (%#v, %v), want TCP fallback answer", observation, err)
	}
	calls := dialer.snapshot()
	if len(calls) != 2 || calls[0].network != "udp" || calls[1].network != "tcp" || !calls[1].conn.sawTCPFraming {
		t.Fatalf("fallback calls = %#v, want UDP then framed TCP", calls)
	}
}

func TestWireSourceClassifiesNegativeDNSSECAndEDE(t *testing.T) {
	t.Parallel()
	resolver := Resolver{ID: "1.0.0.1:53", Name: "recursive"}
	tests := []struct {
		name         string
		flags        uint16
		answer       bool
		authority    bool
		ede          bool
		wantStatus   ResponseStatus
		wantDNSSEC   DNSSECState
		wantNegative time.Duration
		wantStale    bool
	}{
		{name: "AD answer", flags: 0x0020, answer: true, wantStatus: ResponseAnswer, wantDNSSEC: DNSSECSecure},
		{name: "insecure answer", answer: true, wantStatus: ResponseAnswer, wantDNSSEC: DNSSECInsecure},
		{name: "NXDOMAIN with SOA minimum", flags: 0x0023, authority: true, wantStatus: ResponseNXDOMAIN, wantDNSSEC: DNSSECSecure, wantNegative: 45 * time.Second},
		{name: "NODATA with SOA minimum", flags: 0x0020, authority: true, wantStatus: ResponseNODATA, wantDNSSEC: DNSSECSecure, wantNegative: 45 * time.Second},
		{name: "SERVFAIL", flags: 0x0002, wantStatus: ResponseSERVFAIL, wantDNSSEC: DNSSECIndeterminate},
		{name: "EDE stale answer", flags: 0x0020, answer: true, ede: true, wantStatus: ResponseAnswer, wantDNSSEC: DNSSECSecure, wantStale: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
			dialer.handlers[resolver.ID] = func(_ string, raw []byte) ([]byte, error) {
				query, err := parseWireQuestion(raw)
				if err != nil || requireEDNSDO(query) != nil {
					return nil, errors.New("invalid classified query")
				}
				var answers, authority, additional [][]byte
				if test.answer {
					answers = [][]byte{wireResource(query.name, query.typeID, 60, wireA("192.0.2.80"))}
				}
				if test.authority {
					authority = [][]byte{wireResource("example.test.", uint16(dnscheck.RecordSOA), 300, wireSOA(45))}
				}
				if test.ede {
					additional = [][]byte{wireEDEStale()}
				}
				return wireResponse(query, test.flags, answers, authority, additional), nil
			}
			source := newScriptedWireSource(t, dialer, []Resolver{resolver})
			observation, err := source.Observe(context.Background(), "operation-classify", resolver, "www.example.test.", []dnscheck.RecordType{dnscheck.RecordA})
			if err != nil || observation.Status != test.wantStatus || observation.DNSSEC != test.wantDNSSEC ||
				observation.NegativeTTL != test.wantNegative || observation.Stale != test.wantStale {
				t.Fatalf("Observe() = (%#v, %v), want status=%s dnssec=%s negative=%s stale=%t",
					observation, err, test.wantStatus, test.wantDNSSEC, test.wantNegative, test.wantStale)
			}
		})
	}
}

type scriptedTimeoutError struct{}

func (scriptedTimeoutError) Error() string   { return "scripted timeout" }
func (scriptedTimeoutError) Timeout() bool   { return true }
func (scriptedTimeoutError) Temporary() bool { return true }

func TestWireSourceRejectsMismatchedOrUnboundedResponses(t *testing.T) {
	t.Parallel()
	resolver := Resolver{ID: "8.8.8.8:53", Name: "recursive"}
	tests := []struct {
		name   string
		mutate func(wireQuestion, []byte) ([]byte, error)
	}{
		{name: "response ID mismatch", mutate: func(query wireQuestion, response []byte) ([]byte, error) {
			binary.BigEndian.PutUint16(response[:2], query.id+1)
			return response, nil
		}},
		{name: "question mismatch", mutate: func(query wireQuestion, response []byte) ([]byte, error) {
			wrong := query
			wrong.request = append([]byte(nil), query.request...)
			wrongQuestion := wireName("other.example.test.")
			wrongQuestion = binary.BigEndian.AppendUint16(wrongQuestion, query.typeID)
			wrongQuestion = binary.BigEndian.AppendUint16(wrongQuestion, 1)
			wrong.request = append(append(wrong.request[:12:12], wrongQuestion...), query.request[query.end:]...)
			wrong.end = 12 + len(wrongQuestion)
			return wireResponse(wrong, 0x0020, nil, nil, nil), nil
		}},
		{name: "opcode mismatch", mutate: func(_ wireQuestion, response []byte) ([]byte, error) {
			flags := binary.BigEndian.Uint16(response[2:4]) | 0x0800
			binary.BigEndian.PutUint16(response[2:4], flags)
			return response, nil
		}},
		{name: "oversized response", mutate: func(_ wireQuestion, response []byte) ([]byte, error) {
			return append(response, make([]byte, 5000)...), nil
		}},
		{name: "network timeout", mutate: func(_ wireQuestion, _ []byte) ([]byte, error) {
			return nil, scriptedTimeoutError{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
			dialer.handlers[resolver.ID] = func(_ string, raw []byte) ([]byte, error) {
				query, err := parseWireQuestion(raw)
				if err != nil || requireEDNSDO(query) != nil {
					return nil, errors.New("invalid validation query")
				}
				response := wireResponse(query, 0x0020,
					[][]byte{wireResource(query.name, query.typeID, 60, wireA("192.0.2.80"))}, nil, nil)
				return test.mutate(query, response)
			}
			source := newScriptedWireSource(t, dialer, []Resolver{resolver})
			started := time.Now()
			if observation, err := source.Observe(context.Background(), "operation-invalid-response", resolver, "www.example.test.", []dnscheck.RecordType{dnscheck.RecordA}); err == nil {
				t.Fatalf("Observe() = %#v, want rejected %s", observation, test.name)
			}
			calls := dialer.snapshot()
			if len(calls) == 0 || calls[0].conn.deadline.IsZero() || calls[0].conn.deadline.After(started.Add(150*time.Millisecond)) {
				t.Fatalf("query deadline = %v, want bounded by QueryTimeout", calls[0].conn.deadline)
			}
		})
	}
}

func TestWireSourceHonorsCancelledContextWithoutDial(t *testing.T) {
	t.Parallel()
	resolver := Resolver{ID: "8.8.8.8:53", Name: "recursive"}
	dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
	source := newScriptedWireSource(t, dialer, []Resolver{resolver})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Observe(ctx, "operation-cancelled", resolver, "www.example.test.", []dnscheck.RecordType{dnscheck.RecordA}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Observe() error = %v, want context.Canceled", err)
	}
	if calls := dialer.snapshot(); len(calls) != 0 {
		t.Fatalf("cancelled query dialed network: %#v", calls)
	}
}
