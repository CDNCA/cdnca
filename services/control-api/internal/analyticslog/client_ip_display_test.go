package analyticslog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fix-ipdisplay: client_ip is an IPv6 column, so IPv4 clients read back as
// ::ffff:a.b.c.d. Access and block logs must return the dotted IPv4 form; real
// IPv6 addresses stay as they are, and an IPv4 filter still matches.
func TestLogsReturnIPv4MappedClientsAsIPv4(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct{ stored, want, filter string }{
		{stored: "::ffff:203.0.113.61", want: "203.0.113.61"},
		{stored: "::ffff:203.0.113.61", want: "203.0.113.61", filter: "203.0.113.61"},
		{stored: "2001:db8::1", want: "2001:db8::1"},
	}
	for _, item := range cases {
		access := accessTestRow("event-a", now.Add(-time.Minute), "/a")
		access.ClientIP, access.SnapshotMS = item.stored, now.UnixMilli()
		filter := Filter{From: now.Add(-time.Hour), To: now, ClientIP: item.filter}
		client := newUnitClient(t, jsonRowServer(t, access), time.Second)
		page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
		if err != nil || len(page.Items) != 1 || page.Items[0].ClientIP != item.want {
			t.Fatalf("access %q filter %q: %+v, %v", item.stored, item.filter, page.Items, err)
		}

		block := blockEventRow{
			EventID: "event-b", OccurredAtMS: now.Add(-time.Minute).UnixMilli(), SiteID: siteA, NodeID: nodeA,
			RequestID: "request", TraceID: "trace", ConfigVersion: requiredString(configA), Host: "example.test",
			URIPath: "/b", ClientIP: item.stored, CountryCode: "CN", Carrier: "carrier-a", EventType: "waf",
			Action: "block", Severity: "high", RuleID: "rule-a", StatusCode: http.StatusForbidden,
			VersionCount: 1, SnapshotMS: now.UnixMilli(),
		}
		client = newUnitClient(t, jsonRowServer(t, block), time.Second)
		blocks, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
		if err != nil || len(blocks.Items) != 1 || blocks.Items[0].ClientIP != item.want {
			t.Fatalf("block %q filter %q: %+v, %v", item.stored, item.filter, blocks.Items, err)
		}
	}
}

func jsonRowServer(t *testing.T, row any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(writer).Encode(row); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}
