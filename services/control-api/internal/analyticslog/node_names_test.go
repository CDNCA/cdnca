package analyticslog

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

type fixedNodeNames struct {
	names map[string]string
	calls *[][]string
}

func (lookup fixedNodeNames) Lookup(_ context.Context, ids []string) map[string]string {
	*lookup.calls = append(*lookup.calls, ids)
	return lookup.names
}

// fix-logfields（73 实机 10-27）：访问日志“节点ID”列只有 UUID，页面显示“—”。
// 平台视角的访问行带 node_name（节点名称）；租户视角不查、不返回节点名。
func TestHandlerNamesAccessLogNodeForPlatformOnly(t *testing.T) {
	now := time.Date(2026, 10, 26, 17, 0, 0, 0, time.UTC)
	nodeB := "30000000-0000-4000-8000-00000000000b"
	store := &recordingStore{accessPage: AccessPage{Items: []AccessLog{
		{EventID: "a1", OccurredAt: now.Add(-time.Minute), SiteID: siteA, NodeID: nodeA, ConfigVersion: configA,
			Host: "example.test", URIPath: "/", ClientIP: "8.8.8.8", Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "BYPASS", StatusCode: 200},
		{EventID: "a2", OccurredAt: now.Add(-2 * time.Minute), SiteID: siteA, NodeID: nodeB, ConfigVersion: configA,
			Host: "example.test", URIPath: "/", ClientIP: "8.8.8.8", Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "BYPASS", StatusCode: 200},
	}}}
	values := queryValues(now.Add(-time.Hour), now)
	type row struct {
		NodeName *string `json:"node_name"`
	}
	decode := func(t *testing.T, handler http.Handler, path string) []row {
		t.Helper()
		response := doGET(handler, path, values)
		var body struct{ Data []row }
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body.Data) != 2 {
			t.Fatalf("access = %d %s", response.Code, response.Body.String())
		}
		return body.Data
	}

	var calls [][]string
	lookup := fixedNodeNames{calls: &calls, names: map[string]string{nodeA: "C202610150242321"}}

	platform := newTestHandler(t, store, Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, HandlerConfig{})
	platform.SetNodeNameLookup(lookup)
	got := decode(t, platform, "/v1/admin/analytics/logs/access")
	if len(calls) != 1 || len(calls[0]) != 2 || calls[0][0] != nodeA || calls[0][1] != nodeB {
		t.Fatalf("lookup ids = %v", calls)
	}
	if got[0].NodeName == nil || *got[0].NodeName != "C202610150242321" || got[1].NodeName == nil || *got[1].NodeName != "" {
		t.Fatalf("platform node names = %+v %+v", got[0].NodeName, got[1].NodeName)
	}

	tenant := newTestHandler(t, store, Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}, HandlerConfig{})
	tenant.SetNodeNameLookup(lookup)
	for _, item := range decode(t, tenant, "/v1/analytics/logs/access") {
		if item.NodeName != nil {
			t.Fatalf("tenant row carries node_name %q", *item.NodeName)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("tenant view looked up node names: %v", calls)
	}
}
