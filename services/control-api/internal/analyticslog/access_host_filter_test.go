package analyticslog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fix-waflogdetail2：访问日志带域名筛选时，域名条件必须进 SQL（与 WAF 明细
// 同一实现，支持空格分隔多域名）；原先 SQL 不按域名筛，窗口内有别的域名
// 的请求被返回后，行校验要求域名一致，整页报 ErrInvalidResponse。
func TestAccessLogHostFilterIsPushedIntoQuery(t *testing.T) {
	for name, query := range map[string]string{"access": accessPageSQL, "security": blockEventPageSQL} {
		for _, clause := range []string{
			"host_event_ids AS",
			"FROM " + name + "_event_query_payload_state_v1\n\tPREWHERE {has_host:UInt8} = 1",
			"HAVING has(splitByChar(' ', {host:String}), lower(tupleElement(argMaxMerge(latest_payload_state), 15)))",
			"({has_host:UInt8} = 0 OR event_id IN (SELECT event_id FROM host_event_ids))",
		} {
			if !strings.Contains(query, clause) {
				t.Errorf("%s page query lacks %q", name, clause)
			}
		}
	}
}

func TestAccessLogHostFilterReturnsOnlyListedDomains(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query = string(body)
		row := accessTestRow("event-b", now.Add(-time.Minute), "/b")
		row.Host = "B.example.test"
		_ = json.NewEncoder(writer).Encode(row)
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)
	filter := Filter{From: now.Add(-time.Hour), To: now, Host: "a.example.test b.example.test"}
	page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].EventID != "event-b" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if !strings.Contains(query, "host_event_ids AS") {
		t.Fatalf("access query did not narrow by host")
	}
	ip := netip.MustParseAddr("2001:db8::1")
	if accessRowMatches(accessRow{Host: "c.example.test", URIPath: "/"}, ip, normalizeFilter(filter)) {
		t.Error("row outside the domain list matched")
	}
	if !accessRowMatches(accessRow{Host: "A.example.test", URIPath: "/"}, ip, normalizeFilter(filter)) {
		t.Error("row of a listed domain did not match")
	}
}
