package dnscheck

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	testTenantID = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	testSiteID   = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	testZoneID   = uuid.MustParse("33333333-3333-4333-8333-333333333333")
)

type fakeResolver struct {
	mu       sync.Mutex
	handlers map[string]func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error)
	calls    map[string]int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		handlers: make(map[string]func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error)),
		calls:    make(map[string]int),
	}
}

func (r *fakeResolver) Resolve(ctx context.Context, endpoint ResolverEndpoint, query DNSQuery) (DNSResponse, error) {
	key := fakeKey(endpoint, query)
	r.mu.Lock()
	r.calls[key]++
	handler := r.handlers[key]
	r.mu.Unlock()
	if handler == nil {
		return DNSResponse{}, fmt.Errorf("no fake response for %s", key)
	}
	return handler(ctx, endpoint, query)
}

func (r *fakeResolver) set(endpoint ResolverEndpoint, query DNSQuery, handler func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[fakeKey(endpoint, query)] = handler
}

func (r *fakeResolver) callCount(endpoint ResolverEndpoint, query DNSQuery) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[fakeKey(endpoint, query)]
}

func fakeKey(endpoint ResolverEndpoint, query DNSQuery) string {
	return endpointKey(endpoint) + "|" + query.Name + "|" + recordTypeKey(query.Type)
}

func testEndpoint(t *testing.T, address string, port uint16) ResolverEndpoint {
	t.Helper()
	endpoint, err := NewResolverEndpoint("udp", address, port)
	if err != nil {
		t.Fatalf("NewResolverEndpoint() error = %v", err)
	}
	return endpoint
}

func testChecker(t *testing.T, resolver Resolver, authoritative, public []NamedResolver, now time.Time, attempts, depth int) *Checker {
	t.Helper()
	endpoints := make([]ResolverEndpoint, 0, len(authoritative)+len(public))
	for _, item := range append(append([]NamedResolver(nil), authoritative...), public...) {
		endpoints = append(endpoints, item.Endpoint)
	}
	policy, err := NewEndpointPolicy(endpoints...)
	if err != nil {
		t.Fatalf("NewEndpointPolicy() error = %v", err)
	}
	checker, err := NewChecker(Config{
		Resolver: resolver, EndpointPolicy: policy, AuthoritativeResolvers: authoritative, PublicResolvers: public,
		QueryTimeout: 25 * time.Millisecond, Attempts: attempts, MaxCNAMEDepth: depth, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	return checker
}

func baseRequest(now time.Time, recordType RecordType, values ...string) CheckRequest {
	return CheckRequest{
		TenantID: testTenantID, SiteID: testSiteID, Name: "www.example.test",
		Expected: []ExpectedRecord{{Type: recordType, Values: values}}, TTL: 60,
		PropagationWindow: 5 * time.Minute,
		Provider: ProviderSnapshot{
			TenantID: testTenantID, SiteID: testSiteID, ZoneID: testZoneID, Revision: 7,
			Records: []ProviderRecord{{RecordID: "record-1", Name: "www.example.test", Type: recordType, Value: values[0], TTL: 60}},
		},
	}
}

func answerResponse(authoritative bool, owner string, recordType RecordType, values ...string) DNSResponse {
	answers := make([]DNSRecord, 0, len(values))
	for _, value := range values {
		answers = append(answers, DNSRecord{Name: owner, Type: recordType, TTL: 60, Value: value})
	}
	return DNSResponse{Authoritative: authoritative, Answers: answers}
}

func responseHandler(response DNSResponse) func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) {
	return func(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error) { return response, nil }
}

func queryEnd(query []byte) int {
	offset := 12
	for offset < len(query) && query[offset] != 0 {
		offset += int(query[offset]) + 1
	}
	return offset + 5
}

func wireResponse(query []byte, flags uint16, answers ...[]byte) []byte {
	end := queryEnd(query)
	response := make([]byte, 12, end+64)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8000|flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answers)))
	response = append(response, query[12:end]...)
	for _, answer := range answers {
		response = append(response, answer...)
	}
	return response
}

func wireAnswer(recordType RecordType, ttl uint32, value []byte) []byte {
	answer := []byte{0xc0, 0x0c}
	answer = binary.BigEndian.AppendUint16(answer, uint16(recordType))
	answer = binary.BigEndian.AppendUint16(answer, 1)
	answer = binary.BigEndian.AppendUint32(answer, ttl)
	answer = binary.BigEndian.AppendUint16(answer, uint16(len(value)))
	return append(answer, value...)
}
