package dnspropagation

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

// partialSource answers like scriptedObservationSource but returns errs[id]
// for some endpoints and blocks on block[id] until the context ends.
type partialSource struct {
	mu           sync.Mutex
	delegation   Delegation
	observations map[string]Observation
	errs         map[string]error
	block        map[string]bool
}

func (source *partialSource) Discover(context.Context, string, string) (Delegation, error) {
	return source.delegation, nil
}

func (source *partialSource) Observe(ctx context.Context, _ string, resolver Resolver, _ string,
	_ []dnscheck.RecordType) (Observation, error) {
	source.mu.Lock()
	blocked, err, observation := source.block[resolver.ID], source.errs[resolver.ID], source.observations[resolver.ID]
	source.mu.Unlock()
	if blocked {
		<-ctx.Done()
		return Observation{}, ctx.Err()
	}
	return observation, err
}

var n21Now = time.Date(2026, 10, 24, 10, 3, 14, 0, time.UTC)

var n21Expected = []RRSet{{Type: dnscheck.RecordA, Values: []string{"198.51.100.78", "198.51.100.85"}}}

var n21Public = []Resolver{
	{ID: "198.51.100.10:53", Name: "recursive-a"},
	{ID: "198.51.100.11:53", Name: "recursive-b"},
	{ID: "198.51.100.12:53", Name: "recursive-c"},
}

func n21Answer(role ResolverRole, id string, records []RRSet) Observation {
	return Observation{
		Role: role, ResolverID: id, Status: ResponseAnswer, DNSSEC: DNSSECInsecure,
		Records: records, TTL: 10 * time.Minute, ObservedAt: n21Now,
	}
}

// n21Fixture mirrors the 73 evidence: two NS names, six addresses each
// (five IPv4 and one IPv6), twelve authority endpoints, every one answering
// the expected A records unless the test overrides it.
func n21Fixture() *partialSource {
	source := &partialSource{
		delegation:   Delegation{Zone: "868yun.com."},
		observations: map[string]Observation{},
		errs:         map[string]error{},
		block:        map[string]bool{},
	}
	for nsIndex, name := range []string{"classroom.dnspod.net.", "permanent.dnspod.net."} {
		for host := 1; host <= 6; host++ {
			id := fmt.Sprintf("192.0.2.%d:53", nsIndex*10+host)
			if host == 6 {
				id = fmt.Sprintf("[2001:db8::%d]:53", nsIndex*10+host)
			}
			resolver := Resolver{ID: id, Name: name}
			source.delegation.Authorities = append(source.delegation.Authorities, resolver)
			source.observations[id] = n21Answer(RoleAuthoritative, id, n21Expected)
		}
	}
	for _, resolver := range n21Public {
		source.observations[resolver.ID] = n21Answer(RolePublicRecursive, resolver.ID, n21Expected)
	}
	return source
}

func n21Engine(t *testing.T, source Source) *Engine {
	t.Helper()
	engine, err := NewEngine(Config{
		Source: source, Public: n21Public, PublicQuorum: 2,
		MinTTL: time.Second, MaxTTL: 7 * 24 * time.Hour,
		MinNegativeTTL: time.Second, MaxNegativeTTL: 24 * time.Hour,
		MaxAge: 30 * time.Second, Now: func() time.Time { return n21Now }, Metrics: &metricRecorder{},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func n21Request() Request {
	return Request{
		TenantID:    uuid.MustParse("10000000-0000-4000-8000-000000000021"),
		ZoneID:      uuid.MustParse("20000000-0000-4000-8000-000000000021"),
		OperationID: "dns-propagation-n21", Zone: "868yun.com.", Name: "1e3luduh.cdn.868yun.com.",
		Expected: n21Expected,
	}
}

func unreachable() error {
	return &net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
}

// N21 reproduction: on a control host without IPv6 two AAAA name server
// endpoints are unreachable and one anycast IPv4 node times out; the other
// nine agree with the provider write, so propagation must not fail.
func TestN21ThreeOfTwelveAuthoritiesUnreachableStillConverges(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	source.errs["[2001:db8::6]:53"] = unreachable()
	source.errs["[2001:db8::16]:53"] = unreachable()
	source.errs["192.0.2.13:53"] = context.DeadlineExceeded

	result, err := n21Engine(t, source).Observe(context.Background(), n21Request())
	if err != nil {
		t.Fatalf("Observe() error = %v, want convergence over the nine reachable authorities", err)
	}
	if !result.Success || result.Reason != ReasonConverged || result.LKG != LKGPromote {
		t.Fatalf("result = reason:%q success:%t lkg:%q, want converged", result.Reason, result.Success, result.LKG)
	}
	if result.AuthoritativeVotes != 9 || result.PublicVotes != 3 {
		t.Fatalf("votes = authority:%d public:%d, want 9/3", result.AuthoritativeVotes, result.PublicVotes)
	}
}

func TestN21AllNameServersUnreachableIsUnknown(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	for _, resolver := range source.delegation.Authorities {
		source.errs[resolver.ID] = unreachable()
	}
	result, err := n21Engine(t, source).Observe(context.Background(), n21Request())
	if err != ErrAuthoritiesUnavailable || result.Success {
		t.Fatalf("Observe() = success:%t err:%v, want ErrAuthoritiesUnavailable", result.Success, err)
	}
	if len(result.Skipped) != 12 || result.Skipped[0].Reason != "network_unreachable" {
		t.Fatalf("skipped = %+v, want all twelve authorities reported", result.Skipped)
	}
}

// With two NS names, losing every address of one leaves no strict majority:
// the remaining NS cannot vouch for the one we could not hear from.
func TestN21OneOfTwoNameServersFullyUnreachableIsUnknown(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	for _, resolver := range source.delegation.Authorities {
		if resolver.Name == "permanent.dnspod.net." {
			source.errs[resolver.ID] = &net.OpError{Op: "dial", Net: "udp", Err: syscall.ECONNREFUSED}
		}
	}
	if _, err := n21Engine(t, source).Observe(context.Background(), n21Request()); err != ErrAuthoritiesUnavailable {
		t.Fatalf("Observe() err = %v, want ErrAuthoritiesUnavailable", err)
	}
}

// A reachable authority that still serves the old value keeps the existing
// all-answering-authorities-agree rule: authority_conflict, not success.
func TestN21ReachableAuthorityWithOldValueIsConflict(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	source.errs["[2001:db8::6]:53"] = unreachable()
	source.errs["[2001:db8::16]:53"] = unreachable()
	old := "192.0.2.14:53"
	source.observations[old] = n21Answer(RoleAuthoritative, old,
		[]RRSet{{Type: dnscheck.RecordA, Values: []string{"198.51.100.70"}}})
	result, err := n21Engine(t, source).Observe(context.Background(), n21Request())
	if err != nil || result.Success || result.Reason != ReasonAuthorityConflict {
		t.Fatalf("Observe() = reason:%q success:%t err:%v, want authority_conflict", result.Reason, result.Success, err)
	}
}

// Per-endpoint timeout: one hanging node is cut off at EndpointTimeout and
// skipped, the check still converges well inside the caller's deadline.
func TestN21SlowEndpointIsBoundedBySingleEndpointTimeout(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	source.block["192.0.2.3:53"] = true
	engine, err := NewEngine(Config{
		Source: source, Public: n21Public, PublicQuorum: 2,
		MinTTL: time.Second, MaxTTL: 7 * 24 * time.Hour,
		MinNegativeTTL: time.Second, MaxNegativeTTL: 24 * time.Hour,
		MaxAge: 30 * time.Second, Now: func() time.Time { return n21Now }, Metrics: &metricRecorder{},
		EndpointTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	result, err := engine.Observe(ctx, n21Request())
	if err != nil || !result.Success {
		t.Fatalf("Observe() = success:%t err:%v, want success", result.Success, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Observe() took %v, want bounded by the endpoint timeout", elapsed)
	}
	if len(result.Skipped) != 1 || result.Skipped[0].ResolverID != "192.0.2.3:53" ||
		result.Skipped[0].Name != "classroom.dnspod.net." || result.Skipped[0].Reason != "timeout" {
		t.Fatalf("skipped = %+v, want the hanging endpoint reported", result.Skipped)
	}
}

// A malformed answer is not an availability problem and still fails closed.
func TestN21NonNetworkErrorStillFailsWholeCheck(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	source.errs["192.0.2.2:53"] = errInvalidWireResponse
	if _, err := n21Engine(t, source).Observe(context.Background(), n21Request()); err != errInvalidWireResponse {
		t.Fatalf("Observe() err = %v, want errInvalidWireResponse", err)
	}
}

// Public resolvers lost to network errors below the quorum are Unknown, not
// a public_quorum_pending verdict.
func TestN21PublicQuorumUnreachableIsUnknown(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	source.errs[n21Public[0].ID] = context.DeadlineExceeded
	source.errs[n21Public[1].ID] = unreachable()
	if _, err := n21Engine(t, source).Observe(context.Background(), n21Request()); err != ErrAuthoritiesUnavailable {
		t.Fatalf("Observe() err = %v, want ErrAuthoritiesUnavailable", err)
	}
}

func TestN21WireSourceSkipsUnavailableFamilyWithoutDial(t *testing.T) {
	t.Parallel()
	dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
	source, err := NewWireSource(WireSourceConfig{
		Bootstrap: []Resolver{{ID: "198.51.100.53:53", Name: "bootstrap"}}, DialContext: dialer.DialContext,
		QueryTimeout: 100 * time.Millisecond, Now: func() time.Time { return n21Now },
		FamilyAvailable: func(address netip.Addr) bool { return address.Is4() },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Observe(context.Background(), "op", Resolver{ID: "[2402:4e00:111:fff::c]:53", Name: "permanent.dnspod.net."},
		"1e3luduh.cdn.868yun.com.", []dnscheck.RecordType{dnscheck.RecordA})
	if err != errAddressFamilyUnavailable || endpointUnavailableReason(err) != "address_family_unavailable" {
		t.Fatalf("Observe() err = %v, want errAddressFamilyUnavailable", err)
	}
	if calls := dialer.snapshot(); len(calls) != 0 {
		t.Fatalf("dial calls = %+v, want none", calls)
	}
}

// Skipped endpoints are logged with NS name, address and reason, once per
// unchanged set within skippedLogInterval.
func TestN21SkippedEndpointsLoggedOnceWithDetail(t *testing.T) {
	t.Parallel()
	source := n21Fixture()
	source.errs["[2001:db8::6]:53"] = unreachable()
	var buffer bytes.Buffer
	engine, err := NewEngine(Config{
		Source: source, Public: n21Public, PublicQuorum: 2,
		MinTTL: time.Second, MaxTTL: 7 * 24 * time.Hour,
		MinNegativeTTL: time.Second, MaxNegativeTTL: 24 * time.Hour,
		MaxAge: 30 * time.Second, Now: func() time.Time { return n21Now }, Metrics: &metricRecorder{},
		Logger: slog.New(slog.NewTextHandler(&buffer, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := engine.Observe(context.Background(), n21Request()); err != nil {
			t.Fatal(err)
		}
	}
	text := buffer.String()
	if strings.Count(text, "\n") != 1 || !strings.Contains(text, "classroom.dnspod.net.") ||
		!strings.Contains(text, "[2001:db8::6]:53") || !strings.Contains(text, "network_unreachable") {
		t.Fatalf("log = %q, want one line with NS name, address and reason", text)
	}
}
