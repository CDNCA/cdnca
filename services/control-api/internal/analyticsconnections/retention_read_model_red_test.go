package analyticsconnections

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

const retentionTenant = "11111111-1111-1111-1111-111111111111"
const retentionSubscription = "33333333-3333-3333-3333-333333333333"

func TestRetentionReadModelValidatesBoundedAuthoritativeRows(t *testing.T) {
	model, err := NewRetentionReadModel(RetentionConfig{MaxRows: 2, MaxResponseBytes: 4096, TTL: 400 * 24 * time.Hour, Now: func() time.Time {
		return time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	query := RetentionQuery{TenantID: retentionTenant, SubscriptionID: retentionSubscription,
		From: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC)}
	rows, err := model.Read(context.Background(), query, strings.NewReader(strings.Join([]string{
		retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7),
		retentionRow("2026-08-07T01:00:00Z", "2026-08-07T02:00:00Z", 8),
	}, "\n")+"\n"))
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
	if rows[0].TenantID != retentionTenant || rows[0].SubscriptionID != retentionSubscription || rows[0].Value != 7 || rows[1].Value != 8 {
		t.Fatalf("row scope/value = %#v", rows)
	}
}

func TestRetentionReadModelFailsClosedForSchemaScopeOrderingAndCapacity(t *testing.T) {
	baseQuery := RetentionQuery{TenantID: retentionTenant, SubscriptionID: retentionSubscription,
		From: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC)}
	cases := []struct {
		name  string
		body  string
		query RetentionQuery
		want  error
	}{
		{name: "unknown field", body: retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7)[:len(retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7))-1] + `,"unknown":1}` + "}\n", want: ErrRetentionInvalidResponse},
		{name: "duplicate field", body: `{"metric":"connections","tenant_id":"` + retentionTenant + `","tenant_id":"` + retentionTenant + `"}`, want: ErrRetentionInvalidResponse},
		{name: "tenant mismatch", body: retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7), query: RetentionQuery{TenantID: "22222222-2222-2222-2222-222222222222", SubscriptionID: retentionSubscription, From: baseQuery.From, To: baseQuery.To}, want: ErrRetentionScopeMismatch},
		{name: "zero fact", body: retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 0), want: ErrRetentionInvalidResponse},
		{name: "out of order", body: retentionRow("2026-08-07T01:00:00Z", "2026-08-07T02:00:00Z", 8) + "\n" + retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7), want: ErrRetentionOrder},
		{name: "expired", body: retentionRowWithTTL("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7, "2026-08-07T00:00:00Z"), want: ErrRetentionExpired},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			model, err := NewRetentionReadModel(RetentionConfig{MaxRows: 2, MaxResponseBytes: 4096, TTL: 400 * 24 * time.Hour, Now: func() time.Time {
				return time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
			}})
			if err != nil {
				t.Fatal(err)
			}
			query := baseQuery
			if !test.query.From.IsZero() {
				query = test.query
			}
			_, err = model.Read(context.Background(), query, strings.NewReader(test.body))
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v want=%v", err, test.want)
			}
		})
	}
}

func TestRetentionReadModelRejectsOverLimitAndUnavailableResponses(t *testing.T) {
	model, err := NewRetentionReadModel(RetentionConfig{MaxRows: 1, MaxResponseBytes: 32, TTL: 400 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	query := RetentionQuery{TenantID: retentionTenant, SubscriptionID: retentionSubscription,
		From: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC)}
	if _, err := model.Read(context.Background(), query, strings.NewReader(retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7))); !errors.Is(err, ErrRetentionResponseTooLarge) {
		t.Fatalf("oversized response err=%v", err)
	}
	if _, err := model.Read(context.Background(), query, nil); !errors.Is(err, ErrRetentionUnavailable) {
		t.Fatalf("nil response err=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := model.Read(cancelled, query, strings.NewReader("{}\n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled response err=%v", err)
	}
}

func retentionRow(start, end string, value uint64) string {
	periodEnd, err := time.Parse(time.RFC3339Nano, end)
	if err != nil {
		panic(err)
	}
	return retentionRowWithTTL(start, end, value, periodEnd.Add(DefaultRetentionTTL).Format(time.RFC3339Nano))
}

func retentionRowWithTTL(start, end string, value uint64, ttl string) string {
	return `{"metric":"connections","tenant_id":"` + retentionTenant + `","subscription_id":"` + retentionSubscription + `","period_start":"` + start + `","period_end":"` + end + `","value":` + itoa(value) + `,"finalized_through":"` + end + `","source_watermark":9,"evidence_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retention_until":"` + ttl + `"}`
}

func itoa(value uint64) string {
	return strconv.FormatUint(value, 10)
}
