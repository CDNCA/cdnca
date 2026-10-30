package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestDNSProviderPaginationQueryIsStrictAndBounded(t *testing.T) {
	tests := []struct {
		query      string
		wantLimit  int
		wantCursor string
		wantErr    bool
	}{
		{query: "", wantLimit: 20},
		{query: "limit=1", wantLimit: 1},
		{query: "limit=100&cursor=opaque.cursor", wantLimit: 100, wantCursor: "opaque.cursor"},
		{query: "limit=0", wantErr: true},
		{query: "limit=101", wantErr: true},
		{query: "limit=01", wantErr: true},
		{query: "limit=20&limit=20", wantErr: true},
		{query: "cursor=", wantErr: true},
		{query: "unknown=value", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/v1/dns/providers?"+test.query, nil)
			result, err := parseDNSProviderPageRequest(request)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseDNSProviderPageRequest(%q) = %+v, nil", test.query, result)
				}
				return
			}
			if err != nil || result.Limit != test.wantLimit || result.Cursor != test.wantCursor {
				t.Fatalf("parseDNSProviderPageRequest(%q) = %+v, %v", test.query, result, err)
			}
		})
	}
}
