package dnscheck

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCheckerNegativeResponsesRequireAuthoritativeSOAEvidence(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	tests := []struct {
		name      string
		authority []DNSRecord
	}{
		{name: "wrong owner", authority: []DNSRecord{{Name: "other.test.", Type: RecordSOA, TTL: 300, NegativeTTL: 45, negativeTTLSet: true}}},
		{name: "missing SOA"},
		{name: "zero TTL", authority: []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 0, NegativeTTL: 45, negativeTTLSet: true}}},
		{name: "zero minimum", authority: []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 300, NegativeTTL: 0, negativeTTLSet: true}}},
		{name: "TTL over seven days", authority: []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 7*24*60*60 + 1, NegativeTTL: 45, negativeTTLSet: true}}},
		{name: "minimum over seven days", authority: []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 300, NegativeTTL: 7*24*60*60 + 1, negativeTTLSet: true}}},
	}
	for _, rcode := range []uint8{0, 3} {
		negativeKind := "nodata"
		if rcode == 3 {
			negativeKind = "nxdomain"
		}
		for _, test := range tests {
			t.Run(negativeKind+"/"+test.name, func(t *testing.T) {
				authority := testEndpoint(t, fmt.Sprintf("192.0.2.%d", 120+rcode), 53)
				public := testEndpoint(t, fmt.Sprintf("198.51.100.%d", 120+rcode), 53)
				resolver := newFakeResolver()
				resolver.set(authority, query, responseHandler(DNSResponse{
					Authoritative: true, RCode: rcode, Authority: test.authority,
				}))
				resolver.set(public, query, responseHandler(DNSResponse{RCode: rcode, Authority: test.authority}))
				checker := testChecker(t, resolver,
					[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
					[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)

				wantStatus := ClassificationMalformedResponse
				wantCode := "invalid_negative_soa"
				if rcode == 0 && test.name == "missing SOA" {
					wantStatus = ClassificationMissing
					wantCode = ""
				}
				result, err := checker.Check(t.Context(), baseRequest(now, RecordA, "192.0.2.10"))
				if err != nil || result.Status != wantStatus || len(result.Observations) != 2 {
					t.Fatalf("negative response = (%#v, %v), want %s", result, err, wantStatus)
				}
				for _, observation := range result.Observations {
					if observation.Status != wantStatus || observation.ErrorCode != wantCode {
						t.Fatalf("observation = %#v, want status=%s code=%q", observation, wantStatus, wantCode)
					}
				}
			})
		}
	}
}

func TestCheckerNegativeResponsesUseEnclosingSOAMinimumTTL(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	soa := []DNSRecord{{
		Name: "example.test.", Type: RecordSOA, TTL: 300, NegativeTTL: 45, negativeTTLSet: true,
	}}
	for _, test := range []struct {
		name  string
		rcode uint8
		want  Classification
	}{
		{name: "nodata", want: ClassificationNODATA},
		{name: "nxdomain", rcode: 3, want: ClassificationNXDOMAIN},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := testEndpoint(t, "192.0.2.130", 53)
			public := testEndpoint(t, "198.51.100.130", 53)
			resolver := newFakeResolver()
			resolver.set(authority, query, responseHandler(DNSResponse{
				Authoritative: true, RCode: test.rcode, Authority: soa,
			}))
			resolver.set(public, query, responseHandler(DNSResponse{RCode: test.rcode, Authority: soa}))
			checker := testChecker(t, resolver,
				[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
				[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)

			result, err := checker.Check(t.Context(), baseRequest(now, RecordA, "192.0.2.10"))
			if err != nil || result.Status != test.want || len(result.Observations) != 2 {
				t.Fatalf("valid negative response = (%#v, %v), want %s", result, err, test.want)
			}
			for _, observation := range result.Observations {
				if observation.MinimumTTL != 45 {
					t.Fatalf("observation = %#v, want negative TTL 45", observation)
				}
			}
		})
	}
}

func TestCheckerNegativeSOAValidationPreservesPositiveAndQuorumSemantics(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	authoritative := make([]NamedResolver, 0, 3)
	public := make([]NamedResolver, 0, 3)
	resolver := newFakeResolver()
	for index := 0; index < 3; index++ {
		authority := NamedResolver{
			Name:     fmt.Sprintf("ns%d.example.test", index+1),
			Endpoint: testEndpoint(t, fmt.Sprintf("192.0.2.%d", 140+index), 53),
		}
		recursive := NamedResolver{
			Name:     fmt.Sprintf("recursive-%d", index+1),
			Endpoint: testEndpoint(t, fmt.Sprintf("198.51.100.%d", 140+index), 53),
		}
		value := "192.0.2.10"
		if index == 2 {
			value = "192.0.2.20"
		}
		authorityResponse := answerResponse(true, query.Name, RecordA, value)
		authorityResponse.Authority = []DNSRecord{{Name: "other.test.", Type: RecordSOA, TTL: 0}}
		publicResponse := answerResponse(false, query.Name, RecordA, value)
		publicResponse.Authority = authorityResponse.Authority
		resolver.set(authority.Endpoint, query, responseHandler(authorityResponse))
		resolver.set(recursive.Endpoint, query, responseHandler(publicResponse))
		authoritative = append(authoritative, authority)
		public = append(public, recursive)
	}
	checker := testChecker(t, resolver, authoritative, public, now, 1, 4)
	result, err := checker.Check(context.Background(), baseRequest(now, RecordA, "192.0.2.10"))
	if err != nil || result.Status != ClassificationHealthy {
		t.Fatalf("positive strict-majority result = (%#v, %v), want healthy", result, err)
	}
	for _, observation := range result.Observations {
		if observation.MinimumTTL != 60 {
			t.Fatalf("positive observation = %#v, want answer TTL 60", observation)
		}
	}
}
