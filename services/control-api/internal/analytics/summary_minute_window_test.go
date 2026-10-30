package analytics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 数据分析页的“10 分钟 / 30 分钟”预设发出非整点区间；summary SQL 按毫秒精度的
// occurred_at 过滤（query.go summarySQL），因此只要求分钟对齐。按小时分桶的
// 趋势/封禁趋势仍要求整点。
func TestSummaryAcceptsMinuteAlignedWindowButTrendStaysHourly(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		// 800 bytes * 8 / 600 s
		_, _ = io.WriteString(writer, strings.Replace(summaryResponse(), `"average_bandwidth_bps":0.8888888889`, `"average_bandwidth_bps":10.666666666666666`, 1))
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	filter := Filter{From: time.Date(2099, 1, 1, 0, 50, 0, 0, time.UTC), To: time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)}
	if _, err := client.Summary(context.Background(), AdminScope(), filter); err != nil {
		t.Fatalf("10-minute summary: %v", err)
	}
	if _, err := client.Trend(context.Background(), AdminScope(), filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("10-minute trend error = %v, want ErrInvalidInput", err)
	}
	seconds := filter
	seconds.From = seconds.From.Add(time.Second)
	if _, err := client.Summary(context.Background(), AdminScope(), seconds); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("second-aligned summary error = %v, want ErrInvalidInput", err)
	}

	service, err := NewService(&fakeSummaryStore{})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	if _, err := service.Summary(context.Background(), actor, QueryRequest{Audience: AudienceTenant, From: filter.From, To: filter.To}); err != nil {
		t.Fatalf("service 10-minute summary: %v", err)
	}
}

type fakeSummaryStore struct{ QueryStore }

func (*fakeSummaryStore) Summary(context.Context, Scope, Filter) (Summary, error) { return Summary{}, nil }
