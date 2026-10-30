package analyticslog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// NF34: history of IPs auto-banned by CC rules, aggregated from the security
// log's cc/temporary_ban events (one row per site + IP + rule).
func TestListCCBansAggregatesTemporaryBanEvents(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var body string
	var query url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		body, query = string(encoded), request.URL.Query()
		_, _ = io.WriteString(writer, `{"site_id":"`+siteA+`","host":"a.example.test","client_ip":"::ffff:192.0.2.9","rule_id":"018f1000-0000-7000-8000-000000000026","ban_count":3,"first_banned_at_ms":1784800000000,"last_banned_at_ms":1784803000000}`+"\n")
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)
	filter := Filter{From: now.Add(-24 * time.Hour), To: now, ClientIP: "192.0.2.9"}
	page, err := client.ListCCBans(context.Background(), scope{tenantID: tenantA}, filter, 50)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("ListCCBans() = %#v, %v", page, err)
	}
	item := page.Items[0]
	if item.ClientIP != "192.0.2.9" || item.BanCount != 3 || item.RuleID != "018f1000-0000-7000-8000-000000000026" ||
		item.Host != "a.example.test" || !item.FirstBannedAt.Equal(time.UnixMilli(1784800000000).UTC()) ||
		!item.LastBannedAt.Equal(time.UnixMilli(1784803000000).UTC()) {
		t.Fatalf("item = %#v", item)
	}
	for _, token := range []string{"event_type = 'cc'", "action = 'temporary_ban'", "GROUP BY site_id, client_ip, rule_id",
		"ORDER BY last_banned_at_ms DESC", "{row_limit:UInt16}"} {
		if !strings.Contains(body, token) {
			t.Fatalf("query missing %q: %s", token, body)
		}
	}
	if strings.Contains(body, tenantA) || query.Get("param_tenant_id") != tenantA || query.Get("param_client_ip") != "192.0.2.9" ||
		query.Get("param_row_limit") != "51" {
		t.Fatalf("parameters = %#v", query)
	}

	// Rows that break the contract fail closed.
	for name, row := range map[string]string{
		"zero count":     `{"site_id":"` + siteA + `","host":"a","client_ip":"192.0.2.9","rule_id":"r","ban_count":0,"first_banned_at_ms":1784800000000,"last_banned_at_ms":1784800000000}`,
		"reversed times": `{"site_id":"` + siteA + `","host":"a","client_ip":"192.0.2.9","rule_id":"r","ban_count":1,"first_banned_at_ms":1784803000000,"last_banned_at_ms":1784800000000}`,
		"bad ip":         `{"site_id":"` + siteA + `","host":"a","client_ip":"nope","rule_id":"r","ban_count":1,"first_banned_at_ms":1784800000000,"last_banned_at_ms":1784800000000}`,
	} {
		bad := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.Copy(io.Discard, request.Body)
			_, _ = io.WriteString(writer, row+"\n")
		}))
		if _, err := newUnitClient(t, bad, time.Second).ListCCBans(context.Background(), scope{tenantID: tenantA}, filter, 50); err == nil {
			t.Errorf("%s accepted", name)
		}
		bad.Close()
	}
}

type ccBanTestStore struct {
	*recordingStore
	page CCBanPage
	last Filter
}

func (store *ccBanTestStore) ListCCBans(_ context.Context, _ scope, filter Filter, _ uint16) (CCBanPage, error) {
	store.last = filter
	return store.page, nil
}

func TestCCBanHistoryRoute(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := &ccBanTestStore{recordingStore: &recordingStore{}, page: CCBanPage{Items: []CCBan{{
		SiteID: siteA, Host: "a.example.test", ClientIP: "192.0.2.9", RuleID: "r-1", BanCount: 2,
		FirstBannedAt: now.Add(-time.Hour), LastBannedAt: now,
	}}, SnapshotAt: now}}
	handler := newTestHandler(t, store, Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}, HandlerConfig{})
	values := queryValues(now.Add(-24*time.Hour), now)
	values.Set("client_ip", "192.0.2.9")
	values.Set("site_id", siteA)
	response := doGET(handler, "/v1/analytics/logs/cc-bans", values)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var decoded struct {
		Data []struct {
			ClientIP      string `json:"client_ip"`
			BanCount      uint64 `json:"ban_count"`
			LastBannedAt  string `json:"last_banned_at"`
			FirstBannedAt string `json:"first_banned_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil || len(decoded.Data) != 1 ||
		decoded.Data[0].ClientIP != "192.0.2.9" || decoded.Data[0].BanCount != 2 ||
		decoded.Data[0].LastBannedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("body = %s (%v)", response.Body.String(), err)
	}
	if store.last.ClientIP != "192.0.2.9" || store.last.SiteID != siteA {
		t.Fatalf("filter = %#v", store.last)
	}
	for _, extra := range []string{"cursor=abc", "uri_path=%2Fa", "method=GET"} {
		raw := values.Encode() + "&" + extra
		if response := doRawGET(handler, "/v1/analytics/logs/cc-bans", raw); response.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d", extra, response.Code)
		}
	}
}
