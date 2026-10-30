package dnscheck

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestDNSWireCapturesSOAAuthorityNegativeTTL(t *testing.T) {
	query, err := buildDNSQuery(77, DNSQuery{Name: "www.example.test.", Type: RecordA})
	if err != nil {
		t.Fatal(err)
	}
	name := []byte{2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
	mail := []byte{5, 'a', 'd', 'm', 'i', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
	rdata := append(append([]byte(nil), name...), mail...)
	for _, value := range []uint32{1, 2, 3, 4, 45} {
		rdata = binary.BigEndian.AppendUint32(rdata, value)
	}
	response := wireResponse(query, 0x0400)
	binary.BigEndian.PutUint16(response[8:10], 1)
	response = append(response, wireAnswer(RecordSOA, 300, rdata)...)
	parsed, err := parseDNSMessage(response, 512)
	if err != nil || len(parsed.authority) != 1 || parsed.authority[0].TTL != 300 || parsed.authority[0].NegativeTTL != 45 {
		t.Fatalf("parseDNSMessage() = (%#v, %v), want SOA negative TTL 45", parsed, err)
	}
}

func TestCheckerHonorsWireSOAMinimumZero(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	wireQuery, err := buildDNSQuery(78, query)
	if err != nil {
		t.Fatal(err)
	}
	name := []byte{2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
	mail := []byte{5, 'a', 'd', 'm', 'i', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
	rdata := append(append([]byte(nil), name...), mail...)
	for _, value := range []uint32{1, 2, 3, 4, 0} {
		rdata = binary.BigEndian.AppendUint32(rdata, value)
	}
	wire := wireResponse(wireQuery, 0x0400)
	binary.BigEndian.PutUint16(wire[8:10], 1)
	wire = append(wire, wireAnswer(RecordSOA, 300, rdata)...)
	parsed, err := parseDNSMessage(wire, 512)
	if err != nil {
		t.Fatal(err)
	}
	authority := testEndpoint(t, "192.0.2.113", 53)
	public := testEndpoint(t, "198.51.100.113", 53)
	resolver := newFakeResolver()
	resolver.set(authority, query, responseHandler(DNSResponse{Authoritative: true, Authority: parsed.authority}))
	resolver.set(public, query, responseHandler(DNSResponse{Authority: parsed.authority}))
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
		[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || len(result.Observations) != 2 || result.Observations[0].MinimumTTL != 0 || result.Observations[1].MinimumTTL != 0 {
		t.Fatalf("checker SOA MINIMUM=0 = (%#v, %v), want zero negative TTL", result.Observations, err)
	}
}

func TestCheckerQuorumToleratesOneStaleResolver(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	authority := []NamedResolver{
		{Name: "ns1.example.test", Endpoint: testEndpoint(t, "192.0.2.101", 53)},
		{Name: "ns2.example.test", Endpoint: testEndpoint(t, "192.0.2.102", 53)},
		{Name: "ns3.example.test", Endpoint: testEndpoint(t, "192.0.2.103", 53)},
	}
	public := []NamedResolver{
		{Name: "recursive-a", Endpoint: testEndpoint(t, "198.51.100.101", 53)},
		{Name: "recursive-b", Endpoint: testEndpoint(t, "198.51.100.102", 53)},
		{Name: "recursive-c", Endpoint: testEndpoint(t, "198.51.100.103", 53)},
	}
	resolver := newFakeResolver()
	for index, item := range authority {
		value := "192.0.2.10"
		if index == 2 {
			value = "192.0.2.20"
		}
		resolver.set(item.Endpoint, query, responseHandler(answerResponse(true, query.Name, RecordA, value)))
	}
	for index, item := range public {
		value := "192.0.2.10"
		if index == 2 {
			value = "192.0.2.20"
		}
		resolver.set(item.Endpoint, query, responseHandler(answerResponse(false, query.Name, RecordA, value)))
	}
	checker := testChecker(t, resolver, authority, public, now, 1, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationHealthy {
		t.Fatalf("quorum Check() = (%#v, %v), want healthy", result, err)
	}
}

func TestCheckerClassifiesNODATAAndCapturesSOANegativeTTL(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	authority := testEndpoint(t, "192.0.2.111", 53)
	public := testEndpoint(t, "198.51.100.111", 53)
	response := DNSResponse{
		Authority: []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 180}},
	}
	resolver := newFakeResolver()
	resolver.set(authority, query, responseHandler(DNSResponse{Authoritative: true, Authority: response.Authority}))
	resolver.set(public, query, responseHandler(response))
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
		[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationNODATA {
		t.Fatalf("NODATA Check() = (%#v, %v)", result, err)
	}
	if len(result.Observations) != 2 || result.Observations[0].MinimumTTL != 180 || result.Observations[1].MinimumTTL != 180 {
		t.Fatalf("NODATA observations = %#v, want SOA TTL 180", result.Observations)
	}
}

func TestCheckerRejectsNonAuthoritativeNXDOMAINForAuthorityQuorum(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	authority := testEndpoint(t, "192.0.2.114", 53)
	public := testEndpoint(t, "198.51.100.114", 53)
	resolver := newFakeResolver()
	resolver.set(authority, query, responseHandler(DNSResponse{RCode: 3}))
	resolver.set(public, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
		[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationResolverFailure || len(result.Observations) == 0 || result.Observations[0].ErrorCode != "not_authoritative" {
		t.Fatalf("non-AA NXDOMAIN = (%#v, %v), want resolver failure/not_authoritative", result, err)
	}
}

func TestCheckerNXDOMAINCapturesSOANegativeTTL(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	authority := testEndpoint(t, "192.0.2.112", 53)
	public := testEndpoint(t, "198.51.100.112", 53)
	soa := []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 90}}
	resolver := newFakeResolver()
	resolver.set(authority, query, responseHandler(DNSResponse{Authoritative: true, RCode: 3, Authority: soa}))
	resolver.set(public, query, responseHandler(DNSResponse{RCode: 3, Authority: soa}))
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
		[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationNXDOMAIN {
		t.Fatalf("NXDOMAIN Check() = (%#v, %v)", result, err)
	}
	if len(result.Observations) != 2 || result.Observations[0].MinimumTTL != 90 || result.Observations[1].MinimumTTL != 90 {
		t.Fatalf("NXDOMAIN observations = %#v, want SOA TTL 90", result.Observations)
	}
}

func TestRepairPlanPreservesUnrelatedTXT(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.Provider.Records = append(request.Provider.Records, ProviderRecord{
		RecordID: "txt-record", Name: request.Name, Type: RecordTXT, Value: "v=spf1 -all", TTL: 300,
	})
	normalized, err := normalizeRequest(request, now)
	if err != nil {
		t.Fatalf("normalizeRequest() error = %v", err)
	}
	plan, err := buildRepairPlan(normalized)
	if err != nil {
		t.Fatalf("buildRepairPlan() error = %v", err)
	}
	for _, operation := range plan.Operations {
		if operation.RecordID == "txt-record" {
			t.Fatalf("unrelated TXT entered repair plan: %#v", operation)
		}
	}
}
