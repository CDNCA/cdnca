package analyticsconnections

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestRetentionQueryRejectsNonCanonicalRangeBeforeIO(t *testing.T) {
	base := RetentionQuery{
		TenantID: retentionTenant, SubscriptionID: retentionSubscription,
		From: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC),
	}
	invalid := map[string]RetentionQuery{}
	fromZone := base
	fromZone.From = fromZone.From.In(time.FixedZone("non-UTC", 8*60*60))
	invalid["non-UTC from"] = fromZone
	toZone := base
	toZone.To = toZone.To.In(time.FixedZone("non-UTC", 8*60*60))
	invalid["non-UTC to"] = toZone
	fromSubMillisecond := base
	fromSubMillisecond.From = fromSubMillisecond.From.Add(time.Nanosecond)
	invalid["sub-millisecond from"] = fromSubMillisecond
	toSubMillisecond := base
	toSubMillisecond.To = toSubMillisecond.To.Add(time.Nanosecond)
	invalid["sub-millisecond to"] = toSubMillisecond
	overRetention := base
	overRetention.To = overRetention.From.Add(DefaultRetentionTTL + time.Millisecond)
	invalid["over retention authority"] = overRetention

	for name, query := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := validateRetentionQuery(query); !errors.Is(err, ErrRetentionInvalidRequest) {
				t.Fatalf("validateRetentionQuery() error = %v, want %v", err, ErrRetentionInvalidRequest)
			}
		})
	}

	atLimit := base
	atLimit.To = atLimit.From.Add(DefaultRetentionTTL)
	if err := validateRetentionQuery(atLimit); err != nil {
		t.Fatalf("400-day authority range rejected: %v", err)
	}

	model, err := NewRetentionReadModel(RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	response := &retentionRangeTrackingReader{}
	if _, err := model.Read(context.Background(), fromSubMillisecond, response); !errors.Is(err, ErrRetentionInvalidRequest) || response.reads != 0 {
		t.Fatalf("invalid model read error=%v reads=%d", err, response.reads)
	}

	dispatches := 0
	reader := mustRetentionClickHouseReader(t, RetentionConfig{}, retentionHTTPClient(func(*http.Request) (*http.Response, error) {
		dispatches++
		return nil, errors.New("query must not dispatch")
	}))
	if _, err := reader.Read(context.Background(), overRetention); !errors.Is(err, ErrRetentionInvalidRequest) || dispatches != 0 {
		t.Fatalf("invalid ClickHouse read error=%v dispatches=%d", err, dispatches)
	}
}

type retentionRangeTrackingReader struct {
	reads int
}

func (reader *retentionRangeTrackingReader) Read([]byte) (int, error) {
	reader.reads++
	return 0, io.EOF
}
