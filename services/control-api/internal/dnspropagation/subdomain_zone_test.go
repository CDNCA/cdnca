package dnspropagation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

// N14: a CNAME zone that is a subdomain of the hosted domain (cdn.868yun.com
// under 868yun.com) has no NS set: public resolvers answer its NS query with
// the parent's SOA only. Discovery must start from the hosted apex, while
// the record is still asked by its full name.
func TestEnginePropagatesSubdomainZoneRecordThroughApexAuthority(t *testing.T) {
	t.Parallel()
	const (
		apex      = "868yun.com."
		subdomain = "cdn.868yun.com."
		owner     = "16pkdu5t.cdn.868yun.com."
		nsName    = "ns1.dnspod.test."
	)
	bootstrap := Resolver{ID: "1.1.1.1:53", Name: "bootstrap"}
	authorityAddress := "203.0.113.10:53"
	answer := func(query wireQuestion, flags uint16) []byte {
		return wireResponse(query, flags,
			[][]byte{wireResource(owner, uint16(dnscheck.RecordA), 600, wireA("192.0.2.78"))}, nil, nil)
	}
	dialer := &scriptedWireDialer{handlers: map[string]wireHandler{}}
	dialer.handlers[bootstrap.ID] = func(_ string, raw []byte) ([]byte, error) {
		query, err := parseWireQuestion(raw)
		if err != nil {
			return nil, err
		}
		switch {
		case query.typeID == wireTypeNS && query.name == apex:
			return wireResponse(query, 0,
				[][]byte{wireResource(apex, wireTypeNS, 300, wireName(nsName))}, nil,
				[][]byte{wireResource(nsName, uint16(dnscheck.RecordA), 300, wireA("203.0.113.10"))}), nil
		case query.typeID == wireTypeNS && query.name == subdomain:
			// what 1.1.1.1 answers for cdn.868yun.com NS: NOERROR, the
			// parent's SOA in authority, no answer
			return wireResponse(query, 0, nil,
				[][]byte{wireResource(apex, uint16(dnscheck.RecordSOA), 600, wireSOA(600))}, nil), nil
		case query.typeID == uint16(dnscheck.RecordA) && query.name == owner:
			return answer(query, 0), nil
		}
		return nil, errors.New("unexpected bootstrap query " + query.name)
	}
	dialer.handlers[authorityAddress] = func(_ string, raw []byte) ([]byte, error) {
		query, err := parseWireQuestion(raw)
		if err != nil || query.name != owner || query.typeID != uint16(dnscheck.RecordA) {
			return nil, errors.New("authority asked for something other than the full record name")
		}
		return answer(query, 0x0400), nil
	}
	source := newScriptedWireSource(t, dialer, []Resolver{bootstrap})
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	engine, err := NewEngine(Config{
		Source: source, Public: []Resolver{bootstrap}, PublicQuorum: 1,
		MinTTL: time.Second, MaxTTL: 24 * time.Hour, MinNegativeTTL: time.Second, MaxNegativeTTL: time.Hour,
		MaxAge: time.Minute, Now: func() time.Time { return now }, Metrics: &metricRecorder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		TenantID: uuid.New(), ZoneID: uuid.New(), OperationID: "dns-propagation-n14",
		Name: owner, Expected: []RRSet{{Type: dnscheck.RecordA, Values: []string{"192.0.2.78"}}},
	}

	// The zone name itself has no NS: discovery fails (the live symptom).
	request.Zone = subdomain
	if _, err := engine.Observe(context.Background(), request); err == nil {
		t.Fatal("Observe(zone=cdn.868yun.com.) error = nil, want the NS-less discovery failure")
	}
	// The hosted apex: authority found, the full owner name converges.
	request.Zone = apex
	result, err := engine.Observe(context.Background(), request)
	if err != nil || !result.Success || result.AuthoritativeVotes != 1 || result.PublicVotes != 1 {
		t.Fatalf("Observe(zone=868yun.com.) = (%+v, %v), want converged through the apex authority", result, err)
	}
}
