package analytics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fix-ipdisplay: client_ip is an IPv6 column, so an IPv4 client reads back as
// ::ffff:a.b.c.d. The Top client IP ranking and the WAF top clients render the
// key in SQL (the key is also the cursor and tie-break order), so the query
// must turn mapped addresses into dotted IPv4 and leave real IPv6 as is.
// The expression itself is checked against ClickHouse 25.3 in fix-ipdisplay.md.
func TestRankByIPQueryReturnsIPv4MappedClientsAsIPv4(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		body = string(encoded)
		_, _ = io.WriteString(writer, `{"key":"203.0.113.61","request_count":3,"response_bytes":300}`+"\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	scope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rank(context.Background(), scope, validFilter(), RankByIP, 10, ""); err != nil {
		t.Fatal(err)
	}
	if want := clientIPTextSQL("tupleElement(latest, 5)") + " AS key"; !strings.Contains(body, want) {
		t.Fatalf("rank query lacks %q:\n%s", want, body)
	}
}

func TestWAFTopClientsQueryReturnsIPv4MappedClientsAsIPv4(t *testing.T) {
	if want := "SELECT 'client', " + clientIPTextSQL("client_ip") + ","; !strings.Contains(wafBreakdownSQL, want) {
		t.Fatalf("WAF breakdown lacks %q:\n%s", want, wafBreakdownSQL)
	}
}

func TestClientIPTextSQL(t *testing.T) {
	if got, want := clientIPTextSQL("client_ip"), `replaceRegexpOne(toString(client_ip), '^::ffff:([0-9.]+)$', '\\1')`; got != want {
		t.Fatalf("clientIPTextSQL = %s, want %s", got, want)
	}
}
