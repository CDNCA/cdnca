package dnscheck

import (
	"testing"
	"time"
)

func TestCheckerHonorsPublicNegativeCacheTTLAfterPropagationWindow(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	soa := []DNSRecord{{
		Name: "example.test.", Type: RecordSOA, TTL: 300, NegativeTTL: 45, negativeTTLSet: true,
	}}

	tests := []struct {
		name     string
		response DNSResponse
		want     Classification
	}{
		{name: "nxdomain with live negative cache", response: DNSResponse{RCode: 3, Authority: soa}, want: ClassificationPublicPropagating},
		{name: "nodata with live negative cache", response: DNSResponse{Authority: soa}, want: ClassificationPublicPropagating},
		{name: "nxdomain without soa", response: DNSResponse{RCode: 3}, want: ClassificationPublicPropagationFailed},
		{name: "nodata without soa", response: DNSResponse{}, want: ClassificationPublicPropagationFailed},
		{name: "stale positive value", response: answerResponse(false, query.Name, RecordA, "192.0.2.20"), want: ClassificationPublicPropagationFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := testEndpoint(t, "192.0.2.180", 53)
			public := testEndpoint(t, "198.51.100.180", 53)
			resolver := newFakeResolver()
			resolver.set(authority, query, responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")))
			resolver.set(public, query, responseHandler(test.response))
			checker := testChecker(t, resolver,
				[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
				[]NamedResolver{{Name: "recursive-a", Endpoint: public}}, now, 1, 4)
			request := baseRequest(now, RecordA, "192.0.2.10")
			request.PropagationStartedAt = timePointer(now.Add(-request.PropagationWindow - time.Second))

			result, err := checker.Check(t.Context(), request)
			if err != nil || result.Status != test.want {
				t.Fatalf("Check() = (%#v, %v), want %s", result, err, test.want)
			}
		})
	}
}
