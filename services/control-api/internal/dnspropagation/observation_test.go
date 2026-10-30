package dnspropagation

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type observationCall struct {
	operationID string
	resolver    Resolver
	name        string
	types       []dnscheck.RecordType
}

type scriptedObservationSource struct {
	mu           sync.Mutex
	delegation   Delegation
	observations map[string]Observation
	discoverOpID string
	discoverZone string
	calls        []observationCall
}

func (source *scriptedObservationSource) Discover(_ context.Context, operationID, zone string) (Delegation, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.discoverOpID = operationID
	source.discoverZone = zone
	return source.delegation, nil
}

func (source *scriptedObservationSource) Observe(_ context.Context, operationID string, resolver Resolver, name string,
	types []dnscheck.RecordType) (Observation, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls = append(source.calls, observationCall{
		operationID: operationID,
		resolver:    resolver,
		name:        name,
		types:       append([]dnscheck.RecordType(nil), types...),
	})
	return source.observations[resolver.ID], nil
}

func (source *scriptedObservationSource) snapshot() (string, string, []observationCall) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.discoverOpID, source.discoverZone, append([]observationCall(nil), source.calls...)
}

type metricRecorder struct {
	mu      sync.Mutex
	metrics []Metric
}

func (recorder *metricRecorder) Record(metric Metric) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.metrics = append(recorder.metrics, metric)
}

func (recorder *metricRecorder) snapshot() []Metric {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]Metric(nil), recorder.metrics...)
}

func TestEngineObservationContracts(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	tenantID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	zoneID := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	authorityOne := Resolver{ID: "192.0.2.10:53", Name: "ns1.example.test."}
	authorityTwo := Resolver{ID: "192.0.2.11:53", Name: "ns2.example.test."}
	publicOne := Resolver{ID: "198.51.100.10:53", Name: "recursive-a"}
	publicTwo := Resolver{ID: "198.51.100.11:53", Name: "recursive-b"}
	publicThree := Resolver{ID: "198.51.100.12:53", Name: "recursive-c"}
	expected := []RRSet{
		{Type: dnscheck.RecordA, Values: []string{"192.0.2.80"}},
		{Type: dnscheck.RecordAAAA, Values: []string{"2001:db8::80"}},
		{Type: dnscheck.RecordTXT, Values: []string{"acme-proof"}},
	}
	request := Request{
		TenantID:    tenantID,
		ZoneID:      zoneID,
		OperationID: "dns-propagation-operation-1",
		Zone:        "example.test.",
		Name:        "_acme-challenge.www.example.test.",
		Expected:    expected,
	}

	answer := func(role ResolverRole, resolver Resolver, records []RRSet) Observation {
		return Observation{
			Role: role, ResolverID: resolver.ID, Status: ResponseAnswer,
			DNSSEC: DNSSECSecure, Records: records,
			CNAMEChain: []string{"_acme-challenge.delegate.example.test."},
			TTL:        2 * time.Minute, ObservedAt: now,
		}
	}
	nxdomain := func(role ResolverRole, resolver Resolver, ttl time.Duration) Observation {
		return Observation{
			Role: role, ResolverID: resolver.ID, Status: ResponseNXDOMAIN, DNSSEC: DNSSECSecure,
			NegativeTTL: ttl, ObservedAt: now,
		}
	}
	nodata := func(role ResolverRole, resolver Resolver, ttl time.Duration) Observation {
		return Observation{
			Role: role, ResolverID: resolver.ID, Status: ResponseNODATA, DNSSEC: DNSSECSecure,
			NegativeTTL: ttl, ObservedAt: now,
		}
	}
	servfail := func(role ResolverRole, resolver Resolver) Observation {
		return Observation{
			Role: role, ResolverID: resolver.ID, Status: ResponseSERVFAIL,
			DNSSEC: DNSSECIndeterminate, ObservedAt: now,
		}
	}

	tests := []struct {
		name          string
		delegation    Delegation
		public        []Resolver
		quorum        int
		observations  map[string]Observation
		wantNewError  bool
		wantReason    ReasonCode
		wantSuccess   bool
		wantAuthority int
		wantPublic    int
		checkVotes    bool
	}{
		{
			name: "dynamic signed delegation and two of three independent recursive resolvers converge",
			delegation: Delegation{
				Zone: "example.test.", Signed: true,
				Authorities: []Resolver{authorityOne, authorityTwo},
			},
			public: []Resolver{publicOne, publicTwo, publicThree}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: answer(RoleAuthoritative, authorityOne, expected),
				authorityTwo.ID: answer(RoleAuthoritative, authorityTwo, expected),
				publicOne.ID:    answer(RolePublicRecursive, publicOne, expected),
				publicTwo.ID:    answer(RolePublicRecursive, publicTwo, expected),
				publicThree.ID: answer(RolePublicRecursive, publicThree, []RRSet{
					{Type: dnscheck.RecordA, Values: []string{"192.0.2.81"}},
				}),
			},
			wantReason: ReasonConverged, wantSuccess: true,
			wantAuthority: 2, wantPublic: 2, checkVotes: true,
		},
		{
			name:       "public aliases with one vote identity are rejected",
			delegation: Delegation{Zone: "example.test.", Signed: true, Authorities: []Resolver{authorityOne}},
			public: []Resolver{
				publicOne,
				{ID: publicOne.ID, Name: "recursive-a-alias"},
			},
			quorum: 2, wantNewError: true, wantReason: ReasonResolverIdentityConflict,
		},
		{
			name: "authoritative disagreement is fail closed",
			delegation: Delegation{
				Zone: "example.test.", Signed: true,
				Authorities: []Resolver{authorityOne, authorityTwo},
			},
			public: []Resolver{publicOne, publicTwo}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: answer(RoleAuthoritative, authorityOne, expected),
				authorityTwo.ID: answer(RoleAuthoritative, authorityTwo, []RRSet{
					{Type: dnscheck.RecordTXT, Values: []string{"foreign-proof"}},
				}),
				publicOne.ID: answer(RolePublicRecursive, publicOne, expected),
				publicTwo.ID: answer(RolePublicRecursive, publicTwo, expected),
			},
			wantReason: ReasonAuthorityConflict,
		},
		{
			name:       "signed delegation requires secure public quorum",
			delegation: Delegation{Zone: "example.test.", Signed: true, Authorities: []Resolver{authorityOne}},
			public:     []Resolver{publicOne, publicTwo}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: answer(RoleAuthoritative, authorityOne, expected),
				publicOne.ID: func() Observation {
					observation := answer(RolePublicRecursive, publicOne, expected)
					observation.DNSSEC = DNSSECInsecure
					return observation
				}(),
				publicTwo.ID: answer(RolePublicRecursive, publicTwo, expected),
			},
			wantReason: ReasonDNSSECUnverified,
		},
		{
			name:       "public quorum remains pending below threshold",
			delegation: Delegation{Zone: "example.test.", Signed: true, Authorities: []Resolver{authorityOne}},
			public:     []Resolver{publicOne, publicTwo, publicThree}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: answer(RoleAuthoritative, authorityOne, expected),
				publicOne.ID:    answer(RolePublicRecursive, publicOne, expected),
				publicTwo.ID:    servfail(RolePublicRecursive, publicTwo),
				publicThree.ID: answer(RolePublicRecursive, publicThree, []RRSet{
					{Type: dnscheck.RecordTXT, Values: []string{"stale-proof"}},
				}),
			},
			wantReason:    ReasonPublicQuorumPending,
			wantAuthority: 1, wantPublic: 1, checkVotes: true,
		},
		{
			name:       "nxdomain keeps bounded negative TTL evidence",
			delegation: Delegation{Zone: "example.test.", Signed: true, Authorities: []Resolver{authorityOne}},
			public:     []Resolver{publicOne, publicTwo}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: nxdomain(RoleAuthoritative, authorityOne, 45*time.Second),
				publicOne.ID:    nxdomain(RolePublicRecursive, publicOne, 45*time.Second),
				publicTwo.ID:    nxdomain(RolePublicRecursive, publicTwo, 45*time.Second),
			},
			wantReason: ReasonNXDOMAIN,
		},
		{
			name:       "nodata beyond the configured negative TTL bound remains non-success",
			delegation: Delegation{Zone: "example.test.", Signed: true, Authorities: []Resolver{authorityOne}},
			public:     []Resolver{publicOne, publicTwo}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: nodata(RoleAuthoritative, authorityOne, 11*time.Minute),
				publicOne.ID:    nodata(RolePublicRecursive, publicOne, 11*time.Minute),
				publicTwo.ID:    nodata(RolePublicRecursive, publicTwo, 11*time.Minute),
			},
			wantReason: ReasonNODATA,
		},
		{
			name:       "authoritative servfail preserves last known good state",
			delegation: Delegation{Zone: "example.test.", Signed: true, Authorities: []Resolver{authorityOne}},
			public:     []Resolver{publicOne, publicTwo}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: servfail(RoleAuthoritative, authorityOne),
				publicOne.ID:    answer(RolePublicRecursive, publicOne, expected),
				publicTwo.ID:    answer(RolePublicRecursive, publicTwo, expected),
			},
			wantReason: ReasonSERVFAIL,
		},
		{
			name:       "explicit stale answer never promotes even when record values match",
			delegation: Delegation{Zone: "example.test.", Signed: true, Authorities: []Resolver{authorityOne}},
			public:     []Resolver{publicOne, publicTwo}, quorum: 2,
			observations: map[string]Observation{
				authorityOne.ID: answer(RoleAuthoritative, authorityOne, expected),
				publicOne.ID: func() Observation {
					observation := answer(RolePublicRecursive, publicOne, expected)
					observation.Stale = true
					observation.ObservedAt = now.Add(-11 * time.Minute)
					return observation
				}(),
				publicTwo.ID: answer(RolePublicRecursive, publicTwo, expected),
			},
			wantReason: ReasonStale,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source := &scriptedObservationSource{
				delegation: test.delegation, observations: test.observations,
			}
			metrics := &metricRecorder{}
			engine, err := NewEngine(Config{
				Source: source, Public: test.public, PublicQuorum: test.quorum,
				MinTTL: time.Second, MaxTTL: 24 * time.Hour,
				MinNegativeTTL: time.Second, MaxNegativeTTL: 10 * time.Minute,
				MaxAge: 10 * time.Minute, Now: func() time.Time { return now }, Metrics: metrics,
			})
			if test.wantNewError {
				if err == nil {
					t.Fatal("NewEngine() error = nil, want resolver identity rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewEngine() error = %v", err)
			}

			result, err := engine.Observe(context.Background(), request)
			if err != nil {
				t.Fatalf("Observe() error = %v", err)
			}
			if result.TenantID != request.TenantID || result.ZoneID != request.ZoneID ||
				result.OperationID != request.OperationID {
				t.Fatalf("result identity = %#v, want request identity", result)
			}
			if result.Reason != test.wantReason || result.Success != test.wantSuccess {
				t.Fatalf("result = %#v, want reason=%q success=%t", result, test.wantReason, test.wantSuccess)
			}
			if result.RequiredPublic != test.quorum {
				t.Fatalf("required public votes = %d, want %d", result.RequiredPublic, test.quorum)
			}
			if test.checkVotes && (result.AuthoritativeVotes != test.wantAuthority || result.PublicVotes != test.wantPublic) {
				t.Fatalf("votes = authority:%d public:%d, want authority:%d public:%d",
					result.AuthoritativeVotes, result.PublicVotes, test.wantAuthority, test.wantPublic)
			}
			wantLKG := LKGPreserve
			if test.wantSuccess {
				wantLKG = LKGPromote
			}
			if result.LKG != wantLKG || result.Compensation != CompensationNone {
				t.Fatalf("recovery actions = LKG:%q compensation:%q, want LKG:%q compensation:%q",
					result.LKG, result.Compensation, wantLKG, CompensationNone)
			}
			for index, observation := range result.Observations {
				if observation.OperationID != request.OperationID {
					t.Fatalf("observation[%d] operation = %q, want %q", index, observation.OperationID, request.OperationID)
				}
			}

			discoveredOperationID, discoveredZone, calls := source.snapshot()
			if discoveredOperationID != request.OperationID || discoveredZone != request.Zone {
				t.Fatalf("Discover() = (%q,%q), want (%q,%q)", discoveredOperationID, discoveredZone,
					request.OperationID, request.Zone)
			}
			wantTypes := []dnscheck.RecordType{dnscheck.RecordA, dnscheck.RecordAAAA, dnscheck.RecordTXT}
			for _, call := range calls {
				if call.operationID != request.OperationID || call.name != request.Name {
					t.Fatalf("Observe() = (%q,%q), want (%q,%q)", call.operationID, call.name,
						request.OperationID, request.Name)
				}
				for _, recordType := range wantTypes {
					if !slices.Contains(call.types, recordType) {
						t.Fatalf("Observe(%s) types = %v, missing %s", call.resolver.ID, call.types, recordType)
					}
				}
			}

			recorded := metrics.snapshot()
			if len(recorded) != 1 || recorded[0].Reason != result.Reason ||
				recorded[0].Success != result.Success ||
				recorded[0].AuthoritativeVotes != result.AuthoritativeVotes ||
				recorded[0].PublicVotes != result.PublicVotes {
				t.Fatalf("metrics = %#v, want one result-correlated metric", recorded)
			}
		})
	}
}
