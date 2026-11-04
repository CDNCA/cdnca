package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestDNSProviderPaginationQueryIsStrictAndBounded(t *testing.T) {
	tests := []struct {
		query      string
		wantLimit  int
		wantCursor string
		wantErr    bool
		// 平台视图筛选参数
		wantScope     string
		wantManagedBy string
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
		{query: "scope_id=4a8b2c64-5a3f-4d58-9d39-12f0c0b2d6a1&managed_by=tenant", wantLimit: 20,
			wantScope: "4a8b2c64-5a3f-4d58-9d39-12f0c0b2d6a1", wantManagedBy: "tenant"},
		{query: "managed_by=platform", wantLimit: 20, wantManagedBy: "platform"},
		{query: "scope_id=not-a-uuid", wantErr: true},
		{query: "scope_id=4A8B2C64-5A3F-4D58-9D39-12F0C0B2D6A1", wantErr: true},
		{query: "scope_id=00000000-0000-0000-0000-000000000000", wantErr: true},
		{query: "managed_by=", wantErr: true},
		{query: "managed_by=other", wantErr: true},
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
			scope := ""
			if result.ScopeID != uuid.Nil {
				scope = result.ScopeID.String()
			}
			if err != nil || result.Limit != test.wantLimit || result.Cursor != test.wantCursor ||
				scope != test.wantScope || result.ManagedBy != test.wantManagedBy {
				t.Fatalf("parseDNSProviderPageRequest(%q) = %+v, %v", test.query, result, err)
			}
		})
	}
}
