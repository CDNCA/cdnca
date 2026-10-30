package dnscheck

import (
	"testing"
	"time"
)

func TestCheckerRejectsAmbiguousNegativeSOAAuthority(t *testing.T) {
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	for _, test := range []struct {
		name  string
		rcode uint8
		ttls  []uint32
	}{
		{name: "nodata/same TTL", ttls: []uint32{90, 90}},
		{name: "nodata/different TTL", ttls: []uint32{90, 120}},
		{name: "nxdomain/same TTL", rcode: 3, ttls: []uint32{90, 90}},
		{name: "nxdomain/different TTL", rcode: 3, ttls: []uint32{90, 120}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := testEndpoint(t, "192.0.2.150", 53)
			public := testEndpoint(t, "198.51.100.150", 53)
			soa := make([]DNSRecord, 0, len(test.ttls))
			for _, ttl := range test.ttls {
				soa = append(soa, DNSRecord{Name: "example.test.", Type: RecordSOA, TTL: ttl})
			}
			resolver := newFakeResolver()
			resolver.set(authority, query, responseHandler(DNSResponse{
				Authoritative: true, RCode: test.rcode, Authority: soa,
			}))
			resolver.set(public, query, responseHandler(DNSResponse{RCode: test.rcode, Authority: soa}))
			checker := testChecker(t, resolver,
				[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
				[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)

			result, err := checker.Check(t.Context(), baseRequest(now, RecordA, "192.0.2.10"))
			if err != nil || result.Status != ClassificationMalformedResponse || len(result.Observations) != 2 {
				t.Fatalf("ambiguous negative response = (%#v, %v), want malformed response", result, err)
			}
			for _, observation := range result.Observations {
				if observation.Status != ClassificationMalformedResponse || observation.ErrorCode != "invalid_negative_soa" {
					t.Fatalf("observation = %#v, want malformed response/invalid_negative_soa", observation)
				}
			}
			for endpointName, endpoint := range map[string]ResolverEndpoint{"authority": authority, "public": public} {
				if calls := resolver.callCount(endpoint, query); calls != 1 {
					t.Fatalf("%s resolver calls = %d, want 1", endpointName, calls)
				}
			}
		})
	}
}

func TestCheckerAcceptsSingleNegativeSOAAuthority(t *testing.T) {
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	for _, test := range []struct {
		name       string
		rcode      uint8
		wantStatus Classification
		wantCode   string
	}{
		{name: "nodata", wantStatus: ClassificationNODATA, wantCode: "nodata"},
		{name: "nxdomain", rcode: 3, wantStatus: ClassificationNXDOMAIN, wantCode: "nxdomain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := testEndpoint(t, "192.0.2.151", 53)
			public := testEndpoint(t, "198.51.100.151", 53)
			response := DNSResponse{
				RCode:     test.rcode,
				Authority: []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 90}},
			}
			resolver := newFakeResolver()
			authorityResponse := response
			authorityResponse.Authoritative = true
			resolver.set(authority, query, responseHandler(authorityResponse))
			resolver.set(public, query, responseHandler(response))
			checker := testChecker(t, resolver,
				[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
				[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)

			result, err := checker.Check(t.Context(), baseRequest(now, RecordA, "192.0.2.10"))
			if err != nil || result.Status != test.wantStatus || len(result.Observations) != 2 {
				t.Fatalf("single SOA %s response = (%#v, %v), want %s", test.name, result, err, test.wantStatus)
			}
			for index, observation := range result.Observations {
				if observation.Status != test.wantStatus || observation.ErrorCode != test.wantCode || observation.MinimumTTL != 90 {
					t.Fatalf("%s observation %d = %#v, want status=%s code=%q TTL=90", test.name, index, observation, test.wantStatus, test.wantCode)
				}
			}
		})
	}
}

func TestMinimumSOANegativeTTLRejectsMultipleRecords(t *testing.T) {
	for _, ttls := range [][]uint32{{90, 90}, {90, 120}} {
		records := []DNSRecord{
			{Name: "example.test.", Type: RecordSOA, TTL: ttls[0]},
			{Name: "example.test.", Type: RecordSOA, TTL: ttls[1]},
		}
		if ttl, found, valid := minimumSOANegativeTTL(records, "www.example.test."); ttl != 0 || !found || valid {
			t.Fatalf("minimumSOANegativeTTL(%v) = (%d, %t, %t), want (0, true, false)", ttls, ttl, found, valid)
		}
	}

	if ttl, found, valid := minimumSOANegativeTTL(
		[]DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 90}},
		"www.example.test.",
	); ttl != 90 || !found || !valid {
		t.Fatalf("single minimumSOANegativeTTL() = (%d, %t, %t), want (90, true, true)", ttl, found, valid)
	}
}
