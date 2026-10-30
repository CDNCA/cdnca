package gateway

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestNodeIDFromCertificateRequiresOneExactURISAN(t *testing.T) {
	valid, _ := url.Parse(nodeSPIFFEPrefix + testNodeID)
	other, _ := url.Parse("spiffe://cdn-platform/node/018f47a2-5b9c-7d31-8a60-104c9c0b7180")
	tests := []struct {
		name string
		uris []*url.URL
	}{
		{name: "missing"},
		{name: "multiple", uris: []*url.URL{valid, other}},
		{name: "query", uris: []*url.URL{mustParseURL(t, nodeSPIFFEPrefix+testNodeID+"?role=admin")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := nodeIDFromCertificate(&x509.Certificate{URIs: test.uris}); err == nil {
				t.Fatal("certificate unexpectedly accepted")
			}
		})
	}
	if nodeID, err := nodeIDFromCertificate(&x509.Certificate{URIs: []*url.URL{valid}}); err != nil || nodeID != testNodeID {
		t.Fatalf("valid certificate identity = %q, %v", nodeID, err)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
