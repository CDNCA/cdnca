package analytics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type packageMetricRangeHTTPClient struct {
	calls int
}

func (client *packageMetricRangeHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.calls++
	periodEnd, err := time.ParseInLocation("2006-01-02 15:04:05.000", request.URL.Query().Get("param_period_end"), time.UTC)
	if err != nil {
		return nil, err
	}
	body := `{"value":1,"observed_at_ms":` + strconv.FormatInt(periodEnd.UnixMilli(), 10) +
		`,"finalized_through_ms":` + strconv.FormatInt(periodEnd.UnixMilli(), 10) +
		`,"source_evidence_digest":"` + strings.Repeat("a", 64) + `"}` + "\n"
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestPackageMetricRejectsRangesOutsideFactRetentionBeforeDispatch(t *testing.T) {
	periodEnd := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	exactRetentionStart := periodEnd.Add(-400 * 24 * time.Hour)
	shortStart := periodEnd.Add(-time.Hour)
	for _, metric := range []string{"traffic_bytes", "bandwidth_bps", "connections"} {
		t.Run(metric+"/exact 400 days", func(t *testing.T) {
			httpClient := &packageMetricRangeHTTPClient{}
			client, err := NewClient(Config{Endpoint: "https://clickhouse.example.test", Database: "analytics_test"}, httpClient)
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			client.WithTenantResolver(sameTenant{})
			result, err := client.PackageMetric(context.Background(), PackageMetricRequest{
				TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, Metric: metric,
				PeriodStart: exactRetentionStart, PeriodEnd: periodEnd,
			})
			if err != nil || httpClient.calls != 1 || !result.FinalizedThrough.Equal(periodEnd) {
				t.Fatalf("result=%#v err=%v calls=%d", result, err, httpClient.calls)
			}
		})

		invalid := []struct {
			name  string
			start time.Time
			end   time.Time
		}{
			{name: "non UTC start", start: shortStart.In(time.FixedZone("offset", 3600)), end: periodEnd},
			{name: "non UTC end", start: shortStart, end: periodEnd.In(time.FixedZone("offset", 3600))},
			{name: "sub millisecond start", start: shortStart.Add(time.Nanosecond), end: periodEnd},
			{name: "sub millisecond end", start: shortStart, end: periodEnd.Add(time.Nanosecond)},
			{name: "over retention", start: exactRetentionStart, end: periodEnd.Add(time.Millisecond)},
		}
		for _, test := range invalid {
			t.Run(metric+"/"+test.name, func(t *testing.T) {
				httpClient := &packageMetricRangeHTTPClient{}
				client, err := NewClient(Config{Endpoint: "https://clickhouse.example.test", Database: "analytics_test"}, httpClient)
				if err != nil {
					t.Fatalf("client: %v", err)
				}
				client.WithTenantResolver(sameTenant{})
				_, err = client.PackageMetric(context.Background(), PackageMetricRequest{
					TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, Metric: metric,
					PeriodStart: test.start, PeriodEnd: test.end,
				})
				if !errors.Is(err, ErrInvalidInput) || httpClient.calls != 0 {
					t.Fatalf("err=%v calls=%d, want ErrInvalidInput before dispatch", err, httpClient.calls)
				}
			})
		}
	}
}
